"""Simple transparent evaluation helpers for real, labeled CSV data."""
import csv, json
from pathlib import Path

def confusion_metrics(y_true, y_pred):
    if len(y_true)!=len(y_pred): raise ValueError("Label arrays must have equal lengths")
    tp=sum(a==1 and b==1 for a,b in zip(y_true,y_pred)); tn=sum(a==0 and b==0 for a,b in zip(y_true,y_pred)); fp=sum(a==0 and b==1 for a,b in zip(y_true,y_pred)); fn=sum(a==1 and b==0 for a,b in zip(y_true,y_pred))
    precision=tp/(tp+fp) if tp+fp else 0.0; recall=tp/(tp+fn) if tp+fn else 0.0; f1=2*precision*recall/(precision+recall) if precision+recall else 0.0
    return {"n":len(y_true),"tp":tp,"tn":tn,"fp":fp,"fn":fn,"precision":precision,"recall":recall,"f1":f1,"false_positive_rate":fp/(fp+tn) if fp+tn else 0.0}

def evaluate_csv(path, label_col="is_disposable", prediction_col="predicted_disposable"):
    with open(path, newline="", encoding="utf-8-sig") as f: rows=list(csv.DictReader(f))
    y=[int(r[label_col]) for r in rows]; p=[int(r[prediction_col]) for r in rows]
    return confusion_metrics(y,p)
