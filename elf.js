const sizeof_Elf64_Ehdr = 64n;
const sizeof_Elf64_Phdr = 56n;
const sizeof_Elf64_Dyn = 16n;
const sizeof_Elf64_Rela = 24n;
const sizeof_Elf64_Sym = 24n;

const offsetof_phnum = 56n;
const offsetof_phoff = 32n;
const offsetof_p_type = 0n;
const offsetof_p_flags = 4n;
const offsetof_p_filesz = 32n;
const offsetof_p_vaddr = 16n;
const offsetof_d_tag = 0n;
const offsetof_d_un_d_val = 8n;
const offsetof_r_info = 8n;
const offsetof_st_name = 0n;
const offsetof_st_value = 8n;

const PT_DYNAMIC = 2n;

const DT_PLTGOT = 3n;
const DT_JMPREL = 23n;
const DT_PLTRELSZ = 2n;
const DT_SYMTAB = 6n;
const DT_STRTAB = 5n;
const DT_STRSZ = 10n;
const DT_RELAENT = 9n;
const DT_RELA = 7n;
const DT_RELASZ = 8n;
const DT_HASH = 4n

const AT_PHDR = 3n;
const AT_PHNUM = 5n;
const AT_ENTRY = 9n;
const AT_RANDOM = 25n;
const AT_PHENT = 4n;
const AT_NULL = 0n

const R_X86_64_GLOB_DAT = 6n;
const R_X86_64_JUMP_SLOT = 7n;

class Elf {
    constructor(base_addr, reader) {
        this.reader = reader;
        this.base_addr = base_addr;
    }

    read(addr, len) {
        let result = 0;
        let offset = Number(addr - this.base_addr)

        if (len == 1) {
            result = this.reader.getUint8(offset)
        } else if (len == 2) {
            result = this.reader.getUint16(offset, true)
        } else if (len == 4) {
            result = this.reader.getUint32(offset, true)
        } else {
            result = this.reader.getBigUint64(offset, true);
        }
        return result;
    }

    elf_hash(sym_name) {
        let h = 0;
        let g;
        let char;

        for (let i = 0; i < sym_name.length; i++) {
            char = Number(sym_name.charCodeAt(i))
            h = (h << 4) + char;
            g = h & 0xf0000000;
            if (g) {
                h ^= g >> 24;
            }
            h &= ~g;
        }
        return h;
    }

    resolve_symbol(sym_name) {
        let dyn_phdr;

        console.log("[+] Resolving symbolfrom ELF image at 0x" + this.base_addr.toString(16));

        let phnum = this.read(this.base_addr + offsetof_phnum, 2);
        let phoff = this.read(this.base_addr + offsetof_phoff, 8);

        for (var i = 0n; i < phnum; i++) {
            let phdr_offset =  phoff + (sizeof_Elf64_Phdr * i);
            let p_type = this.read(this.base_addr + phdr_offset + offsetof_p_type, 4);

            if (p_type == PT_DYNAMIC) {
                dyn_phdr = i;
            }
        }
                
        let dyn_phdr_filesz = this.read(this.base_addr + phoff + sizeof_Elf64_Phdr * dyn_phdr + offsetof_p_filesz, 8);
        let dyn_phdr_vaddr = this.read(this.base_addr + phoff + sizeof_Elf64_Phdr * dyn_phdr + offsetof_p_vaddr, 8);

        for (let i = 0n; i < dyn_phdr_filesz/sizeof_Elf64_Dyn; i++) {
            let dyn_offset =  BigInt(dyn_phdr_vaddr + sizeof_Elf64_Dyn * i);
            let d_tag = this.read(this.base_addr + dyn_offset + offsetof_d_tag, 8);
            let d_val = this.read(this.base_addr + dyn_offset + offsetof_d_un_d_val, 8);

            switch (d_tag) {
                case DT_SYMTAB:
                    this.symtab = d_val;
                    console.log("\t[+] DT_SYMTAB found: 0x" + this.symtab.toString(16))
                    break;
                case DT_STRTAB:
                    this.strtab = d_val;
                    console.log("\t[+] DT_STRTAB found: 0x" + this.strtab.toString(16))
                    break;
                }
        }

        function lookup(sym_name) {
            let i = 0n;
            let sym_ptr;
            let sym_str = "";
            let char;

            while(true) {   
                let sym_offset = BigInt(this.symtab + (i * sizeof_Elf64_Sym));
                let st_name = this.read(sym_offset, 4); 
    
                if (st_name === 0n) {
                    continue
                }
    
                let sym_str_addr = this.strtab + BigInt(st_name);
    
                while (true) {
                    char = this.read(sym_str_addr, 1);
                    if (char == 0)
                        break;
    
                    sym_str += String.fromCharCode(char);
                    sym_str_addr++;
                }
    
                i += 1n;
                sym_str += String.fromCharCode(0);
    
                if (sym_name == sym_str) {
                    sym_ptr = this.base_addr + this.read(sym_offset + offsetof_st_value, 8);
                    console.log("\t[+] " + str + " : " + ptr.toString(16))
                    break;
                }
    
            };
            return sym_ptr;
        }

        return lookup(sym_name);
    }
        
    resolve_symbol_quick(sym_name) {
        let dyn_phdr;
       
        let phnum = BigInt(this.read(this.base_addr + offsetof_phnum, 2));
        let phoff = BigInt(this.read(this.base_addr + offsetof_phoff, 8));

        for (let i = 0n; i < phnum; i++) {
            let offset =  BigInt(phoff + sizeof_Elf64_Phdr * i);
            let p_type = BigInt(this.read(this.base_addr + offset + offsetof_p_type, 4));

            if (p_type == PT_DYNAMIC) {
                dyn_phdr = i;
            }
        }
        
        let dyn_phdr_filesz = BigInt(this.read(this.base_addr + phoff + sizeof_Elf64_Phdr * dyn_phdr + offsetof_p_filesz, 8));
        let dyn_phdr_vaddr = BigInt(this.read(this.base_addr + phoff + sizeof_Elf64_Phdr * dyn_phdr + offsetof_p_vaddr, 8));
        let strtab, symtab, dthash;

        for (let i = 0n; i < dyn_phdr_filesz/sizeof_Elf64_Dyn; i++) {
            let offset =  BigInt(dyn_phdr_vaddr + sizeof_Elf64_Dyn * i);
            let d_tag = BigInt(this.read(this.base_addr + offset + offsetof_d_tag, 8));
            let d_val = BigInt(this.read(this.base_addr + offset + offsetof_d_un_d_val, 8));

            switch (d_tag) {
                case DT_SYMTAB:
                    this.symtab = d_val;
                    break;
                case DT_STRTAB:
                    this.strtab = d_val;
                    break;
                case DT_HASH:
                    this.dthash = d_val;
                default:
                    break;
                }
        }

        function lookup(name_hash, hashtab, symtab, strtab) {
            let nbuckets = BigInt(this.read(hashtab + (0n * 4n), 4));
            let nchains = BigInt(this.read(hashtab + (1n * 4n), 4));
            let buckets = BigInt(hashtab + (2n* 4n));
            let chains = BigInt(buckets + (nbuckets * 4n));
            let h = BigInt(name_hash) % nbuckets;
            
            for (let i = this.read(buckets + (h * 4n), 4); i != 0n; i = this.read(chains + (i * 4n), 4)) {
                sym_offset = this.symtab + (i * sizeof_Elf64_Sym);
                st_name = this.read(sym_offset + offsetof_st_name, 4);

                let sym_str_addr = this.strtab + BigInt(st_name);

                while (true) {
                    char = this.read(sym_str_addr, 1);
                    if (char == 0)
                        break;
                    sym_str += String.fromCharCode(char);
                    sym_str_addr++;
                }
                if (elf_hash(sym_str) == name_hash) {
                    return this.base_addr + this.read(sym_offset + offsetof_st_value, 4);
                }
            }
            return 0n;
        }
        let sym_hash = this.elf_hash(sym_name);
        return lookup(sym_hash, dthash, symtab, strtab);
    }

    resolve_reloc(sym_name, sym_type) {
        let dyn_phdr;
       
        console.log("[+] Resolving relocs for image at 0x"+this.base_addr.toString(16));

        let phnum = this.read(this.base_addr + offsetof_phnum, 2);
        let phoff = this.read(this.base_addr + offsetof_phoff, 8);

        for (let i = 0n; i < phnum; i++) {
            let offset =  phoff + sizeof_Elf64_Phdr * i;
            let p_type = this.read(this.base_addr + offset + offsetof_p_type, 4);
            
            if (p_type == PT_DYNAMIC) {
                dyn_phdr = i;
            }
        }

        let dyn_phdr_filesz = this.read(this.base_addr + phoff + sizeof_Elf64_Phdr * dyn_phdr + offsetof_p_filesz, 8);
        let dyn_phdr_vaddr = this.read(this.base_addr + phoff + sizeof_Elf64_Phdr * dyn_phdr + offsetof_p_vaddr, 8);

        for (let i = 0n; i < dyn_phdr_filesz/sizeof_Elf64_Dyn; i++) {
            let dyn_offset =  dyn_phdr_vaddr + sizeof_Elf64_Dyn * i;
            let d_tag = this.read(this.base_addr + dyn_offset + offsetof_d_tag, 8);
            let d_val = this.read(this.base_addr + dyn_offset + offsetof_d_un_d_val, 8);

            switch (d_tag) {
                case DT_JMPREL:
                    this.jmprel = d_val;
                    break;
                case DT_PLTRELSZ:
                    this.pltrelsz = d_val;
                    break;
                case DT_PLTGOT:
                    this.pltgot = d_val;
                    break;
                case DT_SYMTAB:
                    this.symtab = d_val;
                    break;
                case DT_STRTAB:
                    this.strtab = d_val;
                    break;
                case DT_STRSZ:
                    this.strsz = d_val;
                    break;
                case DT_RELAENT:
                    this.relaent = d_val;
                    break;
                case DT_RELA:
                    this.rel = d_val;
                    break;
                case DT_RELASZ:
                    this.relasz = d_val;
                    break;
                default:
                    break;
            }
        }
        
        let centinel, size;

        if (sym_type == R_X86_64_GLOB_DAT) {
            centinel = this.rel;
            size = this.relasz/this.relaent;
        } else {
            centinel = this.jmprel;
            size = this.pltrelsz/this.relaent;
        }

        for (let i = 0n; i < size; i++) {
            let rela_offset =  centinel + (sizeof_Elf64_Rela * i);
            let r_type = this.read(rela_offset + offsetof_r_info + 0n, 4);
            let r_sym = this.read(rela_offset + offsetof_r_info + 4n, 4);
            let sym_address;

            if (r_type == sym_type) {
                let sym_offset =  this.symtab + BigInt(r_sym) * sizeof_Elf64_Sym;
                if (sym_offset == 0n) {
                    continue;
                }

                let st_name = this.read(sym_offset + offsetof_st_name, 4);
                if (st_name == 0n) {
                    continue;
                }
                
                if (sym_type == R_X86_64_GLOB_DAT) {
                    sym_address = this.base_addr + BigInt(this.read(sym_offset + offsetof_st_value, 4));
                } else {
                    sym_address = this.pltgot + (i + 3n) * 8n;
                }

                if (st_name === 0n) {
                    continue
                }

                let sym_str_addr = this.strtab + BigInt(st_name);
                let sym_str = "";
                let char
                
                while (true) {
                    char = this.read(sym_str_addr, 1);
                    if (char == 0)
                        break;
                    sym_str += String.fromCharCode(char);
                    sym_str_addr++;
                }

                if (sym_name == sym_str) {
                    return sym_address;
                }
            }
        }
    }
}