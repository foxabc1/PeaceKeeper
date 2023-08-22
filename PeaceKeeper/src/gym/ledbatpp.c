/* 
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the 
 * Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
 *
 * It is based on the LEDBAT implementation by Silvio Valenti
 *
 * Updated by Qian Li to conform to LEDBAT++ draft version 01
 * 
 */

#include <linux/module.h>
#include <net/tcp.h>
#include <linux/vmalloc.h>
#include <linux/math64.h>
#include <linux/win_minmax.h>
#include <linux/time64.h>

//tang netlink
#include <linux/init.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>


//tang netlink
#define NETLINK_TEST     30
#define MSG_LEN            125
#define USER_PORT        100

// init cwnd can be set with: sudo ip route add dst_ip/24 via next_hop_ip dev eth0 initcwnd 2 //

#define MIN_CWND 2
// length of base history in minutes
#define BASE_HISTORY_LEN 10
// length of current delay filter in number of samples
#define DELAY_FILTER_LEN 4
// target delay in ms
#define TARGET 60
// decrease constant
#define C 1
#define MAX_RTT 0xffffffff
//tang netlink
struct sock *nlsk = NULL;
extern struct net init_net;
//tang flag
atomic_t netflag;
//tang:loss
atomic_t brst_delivered_start;
atomic_t brst_lost_start;
//tang:during
atomic_t start_time;
//tang:avg rtt
atomic_t global_rtt;
//tang pkg num
atomic_t num_con;
//tang rtt_grad
atomic_t rtt_prev;

//tang mydata for userspace
struct mydata{
	u32 send_ratio;
	u32 loss;
	s64 cur_delay;
	u32 avg_rtt;
	u32 rtt_deviation;
	u32 rtt_gradient;
};

void *data;
int beta = 60;

struct circular_buffer {
	u32 *buffer;
	u8 first;
	u8 last;
	u8 min;
	u8 len;
};

struct ledbatpp {
	struct circular_buffer base_delay_history;
	struct circular_buffer cur_delay_filter;
	u64 cur_sld_start; // current slow down start time in ms
	u64 schd_sld_start; // scheduled slow down start time in ms
	u64 minute_start; // last rollover in ms
	u32 undo_cwnd; // storing latest cwnd 
    u32 snd_nxt; // sequence number of the next packet being sent at the beginning of cwnd reduction. used to mark RTT
    u32 dec_quota; // max allowed cwnd reduction per RTT
    s32 accrued_dec_bytes; // accrued window decrease in the unit of bytes, it can be negative sometimes
    bool can_ss; // if the flow should do slow start or CA
};

//tang netlink send msg
int send_usrmsg(char *pbuf, uint16_t len)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;

    int ret;

    /* 创建sk_buff 空间 */
    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if(!nl_skb)
    {
        return -1;
    }

    /* 设置netlink消息头部 */
    nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_TEST, len, 0);
    if(nlh == NULL)
    {
        nlmsg_free(nl_skb);
        return -1;
    }

    /* 拷贝数据发送 */
    memcpy(nlmsg_data(nlh), pbuf, len);
    ret = netlink_unicast(nlsk, nl_skb, USER_PORT, MSG_DONTWAIT);

    return ret;
}

static int init_circular_buffer(struct circular_buffer *cb, u16 len)
{
	u32 *buffer = kzalloc(len * sizeof(u32), GFP_KERNEL);
	if (buffer == NULL)
		return 1;
	cb->len = len;
	cb->buffer = buffer;
	cb->first = 0;
	cb->last = 0;
	cb->min = 0;
	return 0;
}

static void tcp_ledbatpp_release(struct sock *sk)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	
	if(!ledbatpp->base_delay_history.buffer) // not initialized properly
		return;
	
	kfree(ledbatpp->cur_delay_filter.buffer);
	kfree(ledbatpp->base_delay_history.buffer);
}

static void tcp_ledbatpp_init(struct sock *sk)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if(init_circular_buffer(&ledbatpp->base_delay_history, BASE_HISTORY_LEN + 1))
		return;
	if(init_circular_buffer(&ledbatpp->cur_delay_filter, DELAY_FILTER_LEN + 1))
		return;


	 //tang:set var init
	atomic_set(&netflag,1);
	atomic_set(&brst_delivered_start,0);
	atomic_set(&brst_lost_start,0);
	atomic_set(&start_time,ktime_to_ms(ktime_get_real()));
	atomic_set(&num_con,1);
	atomic_set(&global_rtt,0);
	atomic_set(&rtt_prev,0);

    ledbatpp->minute_start = 0;
	ledbatpp->cur_sld_start = 0;
	ledbatpp->schd_sld_start = 0;
	ledbatpp->snd_nxt = 0;
	ledbatpp->dec_quota = 0;
	ledbatpp->accrued_dec_bytes = 0;
    ledbatpp->undo_cwnd = tp->snd_cwnd;
	ledbatpp->can_ss = true;
}

typedef u32 (*filter_function) (struct circular_buffer *);

// implements the filter_function above
static u32 min_filter(struct circular_buffer *cb)
{
	if (cb->first == cb->last) // empty buffer
		return MAX_RTT;
	return cb->buffer[cb->min];
}

static u32 get_current_delay(struct ledbatpp *ledbatpp, filter_function filter)
{
	return filter(&ledbatpp->cur_delay_filter);
}

static u32 get_base_delay(struct ledbatpp *ledbatpp)
{
	return min_filter(&ledbatpp->base_delay_history);
}

// invoked at the time of loss, used by both duplicate ack and rto losses
static u32 tcp_ledbatpp_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);

	return max_t(u32, tp->snd_cwnd >> 1U, MIN_CWND);
}

// invoked after loss recovery
static void tcp_ledbatpp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	
	if(!ledbatpp->base_delay_history.buffer) // not initialized properly
		return;
	switch (ev) {
	case CA_EVENT_CWND_RESTART: // after idle, cwnd is restarted
		tp->snd_cwnd_cnt = 0;
		ledbatpp->accrued_dec_bytes = 0;
		ledbatpp->snd_nxt = 0;
		ledbatpp->dec_quota = 0;
		ledbatpp->can_ss = true;
		break;
	case CA_EVENT_COMPLETE_CWR: // after fast retransmit and fast recovery
		tp->snd_cwnd_cnt = 0;
		ledbatpp->accrued_dec_bytes = 0;
		ledbatpp->snd_nxt = 0;
		ledbatpp->dec_quota = 0;
		ledbatpp->can_ss = false;
		break;
	case CA_EVENT_LOSS: // rto timer timeout
		tp->snd_cwnd_cnt = 0;
		ledbatpp->accrued_dec_bytes = 0;
		ledbatpp->snd_nxt = 0;
		ledbatpp->dec_quota = 0;
		ledbatpp->can_ss = true;
		break;
	default:
		break;
	}
}

static bool ledbatpp_ai(struct sock *sk, u32 w, u32 acked)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	u32 cwnd = 0, delta, diff, ca = false;
    
	tp->snd_cwnd_cnt += acked;
	if (tp->snd_cwnd_cnt >= w) {
		delta = tp->snd_cwnd_cnt / w;
        cwnd = tp->snd_cwnd + delta;
        tp->snd_cwnd_cnt -= delta * w;
        if (ledbatpp->can_ss && tcp_in_slow_start(tp) && cwnd > tp->snd_ssthresh) {
            diff = cwnd - tp->snd_ssthresh;
            tp->snd_cwnd_cnt += diff * w;
            ca = true;
            tp->snd_cwnd = min3(cwnd, tp->snd_ssthresh, tp->snd_cwnd_clamp);
        } else {
        	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
        }
        ledbatpp->undo_cwnd = tp->snd_cwnd;
	}
	
    return ca;
}

// ledbat++'s own slow start
static bool ledbatpp_slow_start(struct sock *sk, u32 acked, u32 inversed_gain, u32 queue_delay, u32 base_delay)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 now_ms;
	bool ca;
	
	if (tcp_in_initial_slowstart(tp) && queue_delay > (beta * 3 >> 2)) { // quit initial slow start due to delay is large
		tp->snd_ssthresh = tp->snd_cwnd;
		ledbatpp->can_ss = false;
		// schedule the initial slow down
		now_ms = div_u64(tcp_clock_ns(), NSEC_PER_MSEC);
		ledbatpp->schd_sld_start = now_ms + (tp->srtt_us >> 2) / USEC_PER_MSEC;
        tp->snd_cwnd_cnt += acked;
		return true; 
	}
	
    ca = ledbatpp_ai(sk, inversed_gain, acked);
	
	// end of slow start, update slow down start time
	if (tp->snd_cwnd >= tp->snd_ssthresh) { // quit slow start due to ssthresh reached
		ledbatpp->can_ss = false;
		now_ms = div_u64(tcp_clock_ns(), NSEC_PER_MSEC);
		if (tcp_in_initial_slowstart(tp)) {
			ledbatpp->schd_sld_start = now_ms + (tp->srtt_us >> 2) / USEC_PER_MSEC;
		} else { // end of non-initial slow start 
			ledbatpp->schd_sld_start = now_ms + (now_ms - ledbatpp->cur_sld_start) * 9;
			ledbatpp->cur_sld_start = 0;
			ledbatpp->accrued_dec_bytes = 0;
			ledbatpp->snd_nxt = 0;
			ledbatpp->dec_quota = 0;
		} 
	} 
    return ca;
}

static void ledbatpp_decrease_cwnd(struct sock * sk, int off_target, u32 inversed_gain) 
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int dec_p, allw_dec_p;
	
	ledbatpp->accrued_dec_bytes += (-off_target * C * (int)tp->snd_cwnd * (int)inversed_gain - beta) * (int)tp->mss_cache / beta / (int)tp->snd_cwnd / (int)inversed_gain;
	dec_p = ledbatpp->accrued_dec_bytes / (int)tp->mss_cache;
	ledbatpp->accrued_dec_bytes -= dec_p * (int)tp->mss_cache;
	if (dec_p <= ledbatpp->dec_quota){
		allw_dec_p = dec_p;
		ledbatpp->dec_quota -= dec_p;
	} else {
		allw_dec_p = ledbatpp->dec_quota;
		ledbatpp->dec_quota = 0;
	}
	tp->snd_cwnd = max_t(int, (int)tp->snd_cwnd - allw_dec_p, MIN_CWND);
	tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
	ledbatpp->undo_cwnd = tp->snd_cwnd;
}

static void tcp_ledbatpp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 now_ms;
	u32 current_delay, base_delay, queue_delay, inversed_gain;
    int off_target;
    bool ca;
	
	if(!ledbatpp->base_delay_history.buffer) // not initialized properly
		return;
	
	if (!tcp_is_cwnd_limited(sk))
		return;
	
	if ((base_delay = get_base_delay(ledbatpp)) == MAX_RTT) // base_delay not available
		return;
	
	if((current_delay = get_current_delay(ledbatpp, &min_filter)) == MAX_RTT) // current delay not available
		return;

	now_ms = div_u64(tcp_clock_ns(), NSEC_PER_MSEC);
	
	if (ledbatpp->cur_sld_start) { // in slow down
		if (now_ms - ledbatpp->cur_sld_start <= (tp->srtt_us >> 2) / USEC_PER_MSEC) { // stay in slow down for 2 RTTs
			return;
		} else { // quit slow down
			if (tp->snd_cwnd >= tp->snd_ssthresh) { // subsequent slow start quited with loss
				ledbatpp->can_ss = false;
				ledbatpp->schd_sld_start = now_ms + (now_ms - ledbatpp->cur_sld_start) * 9;
				ledbatpp->cur_sld_start = 0;
				ledbatpp->accrued_dec_bytes = 0;
				ledbatpp->snd_nxt = 0;
				ledbatpp->dec_quota = 0;
				tp->snd_cwnd_cnt = 0;
			} else { // do slow start
			}
		}
	} else { // not in slow down
		if (ledbatpp->schd_sld_start && now_ms >= ledbatpp->schd_sld_start) { // should slow down
			tp->snd_ssthresh = tp->snd_cwnd;
			tp->snd_cwnd = MIN_CWND;
			ledbatpp->undo_cwnd = tp->snd_cwnd;
			ledbatpp->cur_sld_start = now_ms; 
			ledbatpp->schd_sld_start = 0;
			ledbatpp->can_ss = true;
			tp->snd_cwnd_cnt = 0;
			return;
		}
		if (!ledbatpp->schd_sld_start && tp->snd_cwnd >= tp->snd_ssthresh) { // initial slow start quited with loss
			ledbatpp->can_ss = false;
			ledbatpp->schd_sld_start = now_ms + (tp->srtt_us >> 2) / USEC_PER_MSEC;
			ledbatpp->cur_sld_start = 0;
			ledbatpp->accrued_dec_bytes = 0;
			ledbatpp->snd_nxt = 0;
			ledbatpp->dec_quota = 0;
			tp->snd_cwnd_cnt = 0;
		}
	}

	queue_delay = current_delay - base_delay;



	off_target = beta - queue_delay;
	//printk("offset:%d,beta:%d\n",off_target,beta);
	printk(KERN_DEBUG
	"offset:%d,beta:%d\n",off_target,beta);
	
	inversed_gain = min_t(u32, 16, DIV_ROUND_UP(2 * beta, base_delay)); 
	if(inversed_gain>2)
		inversed_gain = 2;
	
	if (tcp_in_slow_start(tp) && ledbatpp->can_ss) { // do slow start 
        ca = ledbatpp_slow_start(sk, acked, inversed_gain, queue_delay, base_delay);
		if(!ca) {
            return;
		} else {
            acked = 0; // all acked packets have been added to tp->snd_cwnd_cnt
		}
	}

	// congestion avoidance
	if (off_target >= 0) { // increase cwnd
        ledbatpp_ai(sk, tp->snd_cwnd * inversed_gain, acked);
        ledbatpp->accrued_dec_bytes = 0;
        ledbatpp->snd_nxt = 0;
        ledbatpp->dec_quota = 0;
	} else { // decrease cwnd
		if (ack >= ledbatpp->snd_nxt) { // a new rtt has began, update decrease quota, etc.
			ledbatpp->snd_nxt = tp->snd_nxt;
			ledbatpp->dec_quota = tp->snd_cwnd >> 1;
			ledbatpp->accrued_dec_bytes = 0;
		}
		ledbatpp_decrease_cwnd(sk, off_target, inversed_gain);
		tp->snd_cwnd_cnt = 0;
	}
}

static void add_delay(struct circular_buffer *cb, u32 rtt)
{
	u8 i;

	if (cb->last == cb->first) {
		/*buffer is empty */
		cb->buffer[cb->last] = rtt;
		cb->min = cb->last;
		cb->last++;
		return;
	}

	/*insert the new delay */
	cb->buffer[cb->last] = rtt;
	/* update the min if it is the case */
	if (rtt < cb->buffer[cb->min])
		cb->min = cb->last;

	/* increase the last pointer */
	cb->last = (cb->last + 1) % cb->len;

	if (cb->last == cb->first) {
		if (cb->min == cb->first) {
			/* Discard the min, search a new one */
			cb->min = i = (cb->first + 1) % cb->len;
			while (i != cb->last) {
				if (cb->buffer[i] < cb->buffer[cb->min])
					cb->min = i;
				i = (i + 1) % cb->len;
			}
		}
		/* move the first */
		cb->first = (cb->first + 1) % cb->len;
	}
}

static void update_current_delay(struct ledbatpp *ledbatpp, u32 rtt)
{
	add_delay(&(ledbatpp->cur_delay_filter), rtt);
}

static void update_base_delay(struct ledbatpp *ledbatpp, u32 rtt)
{
	struct circular_buffer *cb = &(ledbatpp->base_delay_history);
	u32 last, now_ms = div_u64(tcp_clock_ns(), NSEC_PER_MSEC);
	
	if (ledbatpp->minute_start == 0)
		ledbatpp->minute_start = now_ms;

	if (cb->last == cb->first) {
		/* empty circular buffer */
		add_delay(cb, rtt);
		return;
	}

	if (now_ms - ledbatpp->minute_start > 60 * MSEC_PER_SEC) {
		/* we have finished a minute */
		ledbatpp->minute_start = now_ms;
		add_delay(cb, rtt);
	} else {
		/* update the last value and the min if it is the case */
		last = (cb->last + cb->len - 1) % cb->len;
		if (rtt < cb->buffer[last]) {
			cb->buffer[last] = rtt;
			if (rtt < cb->buffer[cb->min])
				cb->min = last;
		}
	}
}

static void tcp_ledbatpp_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	//tang
	u32 current_delay = sample->rtt_us / USEC_PER_MSEC;
	
	u32 rtt_ms;
	//printk(KERN_DEBUG
	//"cur_delay = %u",current_delay);
	atomic_add(1,&num_con);
	atomic_add(current_delay,&global_rtt);
	//tang :for rtt deviation
	u32 sum_rtt_d = atomic_read(&global_rtt);
	u32 sum_rtt_d_factor = 0;
	u32 num_d = atomic_read(&num_con);
	u32 avg_rtt_d = sum_rtt_d/num_d;
	u32 rtt_d = ((current_delay - avg_rtt_d) * (current_delay - avg_rtt_d));
	sum_rtt_d_factor = (sum_rtt_d_factor * 100 / 70) + rtt_d;
	if(atomic_read(&netflag)==1){
		//tang:loss
		atomic_set(&brst_delivered_start,tp->delivered);
		atomic_set(&brst_lost_start,tp->lost);	
		//tang:time
		atomic_set(&start_time,ktime_to_ms(ktime_get_real()));
		atomic_set(&netflag,2);
}
	u32 diff = tp->delivered - atomic_read(&brst_delivered_start);
	if((diff>100)&&(atomic_read(&netflag)==2)&&(atomic_read(&num_con)>0)){
		diff = 0;
		u32 dur_ms;
		u32 loss_rate = 0;
		u32 delivered = tp->delivered - atomic_read(&brst_delivered_start);
		u32 lost = tp->lost - atomic_read(&brst_lost_start);
		//tang :avg rtt
		u32 sum_rtt_avg = atomic_read(&global_rtt);
		u32 num_avg = atomic_read(&num_con);
		//((struct mydata *)data)->avg_rtt = sum_rtt_avg/(num_avg * 1000);
		//tang :rtt deviation replace rtt avg
		((struct mydata *)data)->avg_rtt = sum_rtt_d_factor/num_avg;
	
		if(((struct mydata *)data)->avg_rtt<0)
			((struct mydata *)data)->avg_rtt = 0;
		atomic_set(&num_con,1);
		atomic_set(&global_rtt,0);
		//tang: rtt deviation
		((struct mydata *)data)->rtt_deviation = sum_rtt_d_factor/num_avg;
		//printk(KERN_DEBUG
		//"rtt_deviation %u",((struct mydata *)data)->rtt_deviation);
		//tang:loss
		if(delivered) 
			loss_rate = lost * 1000 / delivered;
		((struct mydata *)data)->loss = loss_rate;
		if(((struct mydata *)data)->loss<0)
			((struct mydata *)data)->loss = 0;
		//tang:time
		dur_ms = ktime_to_ms(ktime_get_real()) - atomic_read(&start_time);
		//((struct mydata *)data)->during = dur_ms;
		//if(((struct mydata *)data)->during<0)
			//((struct mydata *)data)->during = 0;
		//tang:send ratio
		if(dur_ms){
			u32 goodput = (delivered * tp->mss_cache * 8) / dur_ms;
			((struct mydata *)data)->send_ratio = goodput;
			if(((struct mydata *)data)->send_ratio<0)
				((struct mydata *)data)->send_ratio = 0;
		}

		//tang:current delay
		((struct mydata *)data)->cur_delay = current_delay ;
		if(((struct mydata *)data)->cur_delay<0)
			((struct mydata *)data)->cur_delay = 0;
		//tang rtt_grad
		((struct mydata *)data)->rtt_gradient = (current_delay - atomic_read(&rtt_prev))/dur_ms;
		atomic_set(&rtt_prev,current_delay);	
		//DEBUG
		//printk(KERN_DEBUG
		//"loss_rate :%u,send_ratio:%u,rtt_gradient %u,rtt_deviation %u",((struct mydata *)data)->loss,((struct mydata *)data)->send_ratio,((struct mydata *)data)->rtt_gradient,((struct mydata *)data)->rtt_deviation);
		send_usrmsg((char *)data, sizeof(struct mydata));
		((struct mydata *)data)->avg_rtt = 0;
		((struct mydata *)data)->rtt_deviation = 0;
		atomic_set(&netflag,1);	

}



	if(!ledbatpp->base_delay_history.buffer) // not initialized properly
		return;

	if (sample->rtt_us <= 0) 
		return;
	
	rtt_ms = sample->rtt_us / USEC_PER_MSEC;
	update_current_delay(ledbatpp, rtt_ms);
	update_base_delay(ledbatpp, rtt_ms);
}

static u32 tcp_ledbatpp_undo_cwnd(struct sock *sk)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	
	if(!ledbatpp->base_delay_history.buffer) { // not initialized properly
		return max(tp->snd_cwnd, tp->prior_cwnd);
	}
	
	return ledbatpp->undo_cwnd;
}



//tang:netlink recv
static void netlink_rcv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    char *umsg = NULL;
    int i;
    int a;

    if(skb->len >= nlmsg_total_size(0))
    {
        nlh = nlmsg_hdr(skb);
        umsg = NLMSG_DATA(nlh);
        if(umsg)
        {
		//tang:flag
		//atomic_set(&netflag,1);
		//printk("kernel recv from user: %s\n", umsg);
		for(i=0;umsg[i]!='\0';i++)
		{
			if(umsg[i]=='\n')
			{
				umsg[i]='\0';
				break;
			}
				
		}
		a = kstrtouint(umsg, 10, &beta);
		//printk("beta:%u",beta);


        }
    }
}
struct netlink_kernel_cfg cfg = { 
        .input  = netlink_rcv_msg, /* set recv callback */
};  



static struct tcp_congestion_ops tcp_ledbatpp = {
	.init = tcp_ledbatpp_init,
	.ssthresh = tcp_ledbatpp_ssthresh,
	.cong_avoid = tcp_ledbatpp_cong_avoid,
	.pkts_acked = tcp_ledbatpp_pkts_acked,
	.undo_cwnd = tcp_ledbatpp_undo_cwnd,
	.cwnd_event = tcp_ledbatpp_cwnd_event,
	.release = tcp_ledbatpp_release,

	.owner = THIS_MODULE,
	.name = "rl1"
};



static int __init tcp_ledbatpp_register(void)
{
	data = kmalloc(sizeof(struct mydata), GFP_KERNEL);
	nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    	if(nlsk == NULL)
    	{   
        	return -1; 
    	}   
	BUILD_BUG_ON(sizeof(struct ledbatpp) > ICSK_CA_PRIV_SIZE);
	
	return tcp_register_congestion_control(&tcp_ledbatpp);
}

static void __exit tcp_ledbatpp_unregister(void)
{
	kfree(data);
	if (nlsk){
        	netlink_kernel_release(nlsk); /* release ..*/
        	nlsk = NULL;
    	}  
	tcp_unregister_congestion_control(&tcp_ledbatpp);
}

module_init(tcp_ledbatpp_register);
module_exit(tcp_ledbatpp_unregister);

MODULE_AUTHOR("Qian Li");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Ledbat Plus Plus");
