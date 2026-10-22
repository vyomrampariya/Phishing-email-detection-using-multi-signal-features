"""Small evaluation utilities. Metrics should only be used on independently labeled real records."""
from __future__ import annotations
from collections import Counter
from typing import Sequence

def binary_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> dict[str, float | int]:
    if len(y_true) != len(y_pred) or not y_true: raise ValueError("labels must be non-empty and equal length")
    tp=sum(a==1 and b==1 for a,b in zip(y_true,y_pred)); tn=sum(a==0 and b==0 for a,b in zip(y_true,y_pred))
    fp=sum(a==0 and b==1 for a,b in zip(y_true,y_pred)); fn=sum(a==1 and b==0 for a,b in zip(y_true,y_pred))
    precision=tp/(tp+fp) if tp+fp else 0.0; recall=tp/(tp+fn) if tp+fn else 0.0
    return {"n":len(y_true),"tp":tp,"tn":tn,"fp":fp,"fn":fn,"precision":precision,"recall":recall,
            "f1":2*precision*recall/(precision+recall) if precision+recall else 0.0,
            "false_positive_rate":fp/(fp+tn) if fp+tn else 0.0,"false_negative_rate":fn/(fn+tp) if fn+tp else 0.0}

def label_distribution(labels: Sequence[str]) -> dict[str, int]: return dict(Counter(labels))
