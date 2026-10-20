"""Metrics helper for externally sourced labeled CSV records."""
def binary_metrics(y_true,y_score,threshold=.5):
    if len(y_true)!=len(y_score) or not y_true:raise ValueError("non-empty equal-length labels and scores required")
    tp=sum(bool(y) and s>=threshold for y,s in zip(y_true,y_score));tn=sum(not bool(y) and s<threshold for y,s in zip(y_true,y_score));fp=len(y_true)-tp-tn-sum(bool(y) and s<threshold for y,s in zip(y_true,y_score));fn=sum(bool(y) and s<threshold for y,s in zip(y_true,y_score))
    precision=tp/(tp+fp) if tp+fp else 0;recall=tp/(tp+fn) if tp+fn else 0
    return {"precision":precision,"recall":recall,"f1":2*precision*recall/(precision+recall) if precision+recall else 0,"confusion_matrix":[[tn,fp],[fn,tp]],"false_positive_rate":fp/(fp+tn) if fp+tn else 0,"false_negative_rate":fn/(fn+tp) if fn+tp else 0,"roc_auc":None}
