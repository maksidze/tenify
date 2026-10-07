import json
s=json.load(open('work/explorer-public-symbols.json'))
a=[r for r in s if any(t in r[1].lower() for t in ('taskview','multitasking','invoketask','toggleview'))]
print('\n'.join(f'{r[0]:x} {r[1]}' for r in a if not any(t in r[1] for t in ('tlg','lambda','WRL','Details','std@@'))))
