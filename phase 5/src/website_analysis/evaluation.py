def binary_metrics(labels,scores,threshold=.5):
    if len(labels)!=len(scores) or not labels:raise ValueError("non-empty labels and scores of equal length required")
    tp=sum(bool(y) and s>=threshold for y,s in zip(labels,scores));fn=sum(bool(y) and s<threshold for y,s in zip(labels,scores));fp=sum(not bool(y) and s>=threshold for y,s in zip(labels,scores));tn=len(labels)-tp-fn-fp
    p=tp/(tp+fp) if tp+fp else 0;r=tp/(tp+fn) if tp+fn else 0
    return {"precision":p,"recall":r,"f1":2*p*r/(p+r) if p+r else 0,"confusion_matrix":[[tn,fp],[fn,tp]],"false_positive_rate":fp/(fp+tn) if fp+tn else 0,"false_negative_rate":fn/(fn+tp) if fn+tp else 0,"roc_auc":None}
