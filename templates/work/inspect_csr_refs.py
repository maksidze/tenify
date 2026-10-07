exec(Path('work/inspect_csr_pfn.py').read_text().split('refs=[]')[0])
refs=[]
for s in h.sections:
 if not s.Characteristics&0x20000000:continue
 data=s.get_data()
 for k in range(len(data)-6):
  if data[k:k+2]==b'\xff\x15' and s.VirtualAddress+k+6+struct.unpack_from('<i',data,k+2)[0]==iat:refs.append(s.VirtualAddress+k)
print(list(map(hex,refs)))
for rv in refs:
 fn=next(x.struct for x in h.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=rv<x.struct.EndAddress)
 Path('work/host-user32-csr-init.txt').write_text(dump(h,fn.BeginAddress,fn.EndAddress-fn.BeginAddress))
