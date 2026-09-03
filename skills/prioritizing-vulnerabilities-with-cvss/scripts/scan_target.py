#!/usr/bin/env python3
import sys, math, re

def w(metric, val):
    tables = {
      "AV":{"N":0.85,"A":0.62,"L":0.55,"P":0.20},
      "AC":{"L":0.77,"H":0.44},
      "PR_U":{"N":0.85,"L":0.62,"H":0.27},
      "PR_C":{"N":0.85,"L":0.68,"H":0.50},
      "UI":{"N":0.85,"R":0.62},
      "S":{"U":None,"C":None},
      "C":{"N":0.00,"L":0.22,"H":0.56},
      "I":{"N":0.00,"L":0.22,"H":0.56},
      "A":{"N":0.00,"L":0.22,"H":0.56},
    }
    return tables[metric][val]

def main():
    if len(sys.argv) != 2:
        print("Usage: python cvss31.py 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'")
        raise SystemExit(2)
    v = sys.argv[1]
    parts = dict(x.split(":") for x in v.split("/")[1:])
    av=w("AV",parts["AV"]); ac=w("AC",parts["AC"]); ui=w("UI",parts["UI"])
    scope=parts["S"]
    pr=w("PR_C" if scope=="C" else "PR_U",parts["PR"])
    c=w("C",parts["C"]); i=w("I",parts["I"]); a=w("A",parts["A"])
    exploit=8.22*av*ac*pr*ui
    iss=1-(1-c)*(1-i)*(1-a)
    if scope=="U":
        impact=6.42*iss
    else:
        impact=7.52*(iss-0.029)-3.25*((iss-0.02)**15)
    if impact <= 0:
        score=0.0
    elif scope=="U":
        score=min(10, math.ceil((impact+exploit)*10)/10)
    else:
        score=min(10, math.ceil(1.08*(impact+exploit)*10)/10)
    rating="None" if score==0 else "Low" if score<=3.9 else "Medium" if score<=6.9 else "High" if score<=8.9 else "Critical"
    print(f"Score: {score:.1f}\nSeverity: {rating}")
if __name__ == "__main__":
    main()
