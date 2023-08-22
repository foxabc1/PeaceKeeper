# Copyright 2019 Nathan Jay and Noga Rotman
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import numpy as np
import math

# The monitor interval class used to pass data from the PCC subsystem to
# the machine learning module.
#
class SenderMonitorInterval():
    def __init__(self,
                 sender_id,
                 send_ratio=0.0,
                 loss=0.0,
                 cur_delay=0.0,	
                 avg_rtt=0.0,
                 rtt_deviation=0.0,	
                 rtt_gradient=0.0						
):
        self.features = {}
        self.sender_id = sender_id
        self.send_ratio = send_ratio
        self.loss = loss
        self.cur_delay = cur_delay
        self.avg_rtt = avg_rtt
        self.rtt_deviation = rtt_deviation
        self.rtt_gradient = rtt_gradient
    def get(self, feature):
        if feature in self.features.keys():
            return self.features[feature]
        else:
            result = SenderMonitorIntervalMetric.eval_by_name(feature, self)
            self.features[feature] = result
            return result

    # Convert the observation parts of the monitor interval into a numpy array
    def as_array(self, features):
        return np.array([self.get(f) / SenderMonitorIntervalMetric.get_by_name(f).scale for f in features])

class SenderHistory():
    def __init__(self, length, features, sender_id):
        self.features = features
        self.values = []        #这个数组存历史数据
        self.sender_id = sender_id
        for i in range(0, length):
            self.values.append(SenderMonitorInterval(self.sender_id))

    def step(self, new_mi):
        self.values.pop(0)          #pop() 函数用于移除列表中的一个元素(默认最后一个元素)，并且返回该元素的值。
        self.values.append(new_mi)              #new_mi是观察到的新数据?

    def as_array(self):
        arrays = []
        for mi in self.values:
            arrays.append(mi.as_array(self.features))       #转化为np数组
        arrays = np.array(arrays).flatten()             #返回一个折叠成一维的数组
        return arrays

class SenderMonitorIntervalMetric():
    _all_metrics = {}       #这个数组干嘛用？

    def __init__(self, name, func, min_val, max_val, scale=1.0):
        self.name = name
        self.func = func
        self.min_val = min_val
        self.max_val = max_val
        self.scale = scale
        SenderMonitorIntervalMetric._all_metrics[name] = self

    def eval(self, mi):
        return self.func(mi)

    def eval_by_name(name, mi):
        return SenderMonitorIntervalMetric._all_metrics[name].eval(mi)          #self.eval(mi)?

    def get_by_name(name):
        return SenderMonitorIntervalMetric._all_metrics[name]       #self?

def get_min_obs_vector(feature_names):
    #print("Getting min obs for %s" % feature_names)
    result = []
    for feature_name in feature_names:
        feature = SenderMonitorIntervalMetric.get_by_name(feature_name)
        result.append(feature.min_val)
    return np.array(result) 

def get_max_obs_vector(feature_names):
    result = []
    for feature_name in feature_names:
        feature = SenderMonitorIntervalMetric.get_by_name(feature_name)
        result.append(feature.max_val)
    return np.array(result) 

def _mi_metric_recv_rate(mi):           #need?
    #dur = mi.get("recv dur")
    #if dur > 0.0:
        #return 8.0 * (mi.bytes_acked - mi.packet_size) / dur
    return 0.0
#add
def _mi_metric_recv_dur(mi):
    return mi.rtt_gradient

def _mi_metric_avg_latency(mi):
	return math.sqrt(mi.avg_rtt)

def _mi_metric_send_rate(mi):       #？
    return mi.send_ratio/1000

def _mi_metric_send_dur(mi):
    return mi.during

def _mi_metric_loss_ratio(mi):
    return mi.loss

def _mi_metric_rtt_deviation(mi):
    return math.sqrt(mi.rtt_deviation)

def _mi_metric_ack_latency_inflation(mi):		#need?
    return 0.0
	
def _mi_metric_sent_latency_inflation(mi):		#need?
    return 0.0

_conn_min_latencies = {}
# min rtt (wo meiyou)
def _mi_metric_conn_min_latency(mi):
	return 0.0
        
#send ratio(wo meiyou)    
def _mi_metric_send_ratio(mi):
	return mi.send_ratio
# min rtt (wo meiyou)
def _mi_metric_latency_ratio(mi):
	return mi.cur_delay

SENDER_MI_METRICS = [
    SenderMonitorIntervalMetric("send rate", _mi_metric_send_rate, 0.0, 1e9, 1e7),
    SenderMonitorIntervalMetric("recv rate", _mi_metric_recv_rate, 0.0, 1e9, 1e7),
    SenderMonitorIntervalMetric("recv dur", _mi_metric_recv_dur, 0.0, 1e7),
    SenderMonitorIntervalMetric("send dur", _mi_metric_send_dur, 0.0, 100.0),
    SenderMonitorIntervalMetric("avg latency", _mi_metric_avg_latency, 0.0, 100.0),
    SenderMonitorIntervalMetric("loss ratio", _mi_metric_loss_ratio, 0.0, 1.0),
    SenderMonitorIntervalMetric("ack latency inflation", _mi_metric_ack_latency_inflation, -1.0, 10.0),
    SenderMonitorIntervalMetric("sent latency inflation", _mi_metric_sent_latency_inflation, -1.0, 10.0),
    SenderMonitorIntervalMetric("conn min latency", _mi_metric_conn_min_latency, 0.0, 100.0),
    SenderMonitorIntervalMetric("rtt_deviation", _mi_metric_rtt_deviation, 0.0, 1e4),
    SenderMonitorIntervalMetric("latency ratio", _mi_metric_latency_ratio, 1.0, 10000.0),
    SenderMonitorIntervalMetric("send ratio", _mi_metric_send_ratio, 0.0, 1000.0)
]



