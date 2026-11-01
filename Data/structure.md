there are some static fields :
- ip, timestamp, scanTime(scantime is timestamp in integer(comes at the end of the path varibale))
- proto --> name of the declared protocol(such as ssh, http, ...)
- port
- appId --> name of the app used for this scan(e.g. zgrab2)
- jid --> i think its about the job that is scanning.(id of a job)
- wip --> it seems like worker ip and allways been local.(did `jq -r '._source.wip // empty' PartOfMe.json | grep -vx 'local' | sort | uniq -c | sort -rn` on the whole dataset and got zero output). i think it points to the way that we are scanning.
- pr & nPr --> `nPr` is most likely to Number of all of the partitions and pr means id of partition `x`(just gussing). `nPr` is allways equal to `"0"`, so can not guss easily.
- host --> seems like container id (not ip). 
- txy --> means port number == xy.
- _dateparsefailure --> means tried to convert `date X` to `@timestamp` but was  unsucssesful.
- 


---
- path is made of {`<appId>_<pr>_<port>_<proto>_<wip>_<jid>_<scanTime>.json`}
pub-zgrab2_0_t22_ssh_local_3_1762417273.json
<!-- --- -->
<!-- now take a look at this : -->
<!-- ![image](َassets/images/whole.png) -->
<!-- --- -->

### CPE
CPE contains many fields such as : 
1) cpe : an static word that will allways comes in the begining of the cpe
2) version : it refers to a standard version of cpe not product version
3) part : 
    Asset Type :
    
    1) a : application
    2) h : hardware
    3) o : Operating System
4) vendor : name of the creator but with the exact same token that is used in NVD dictionary
5) product : name of the product like `open ssh`.
6) version : version of the product
7) update : patch/serviece pack
8) edition : outdated and must be filled with `*` to avoid any conflicts with older CPEs
9) language : will be filled only and only when app has another version written in another language.
10) sw_edition : it comes to seperate products that has same name and version but different edition(such as professional, online, enterprise, comunity and ...)
11) target_sw : aimed targeted sofware surface(f.g. windows, linux) 
12) target_hw : aimed targeted hardware surfac(f.g. amd, x64)
13) other(sth like build id from creator, local code of product)


### but 
8-13 wont come with passive banners so we have to fill cpe with passive banners with just 3-7.

part is our task to fill, not gained from data it self.

## SSH 
in ssh we have a structured output, to find what we want we shall just take a look at `result.server_id.software`. it will give such a things as `OpenSSH_9.6p1` meaning `product + version`.
its a clean and powerfull signal.
```example 
"server_id": {
    "comment": "Ubuntu-3ubuntu13.11",
    "version": "2.0",
    "software": "OpenSSH_9.6p1",
    "raw": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.11"
    }
```

then we can use `.coment`. it talks about os. 

then `.raw` for the full raw baner of ssh

then `.version`.

`key_exchange` or `algo_selection` or `server_key_exchange` are useless. 

gains via zgrab2.
---
## FTP 
gains via `pub-tgrab`.
you may extract cpe from whole `result.banner`.

```example 
banner": "220 a407 FTP server (MikroTik 6.49.18) ready
```
---
## HTTP
this is not static unfortunately and depends on the server.
it mostsly is in : 
1) result.rsponse.headers.server 

but sometimes it includes version and sometimes just name.

---
## MongoDB
it is structured.
we can find it in `result.build_info.version` for the clean version with no need to parse.

`result.build_info.versionArray` contains the same info but in the array form. 

`result.build_info.buildEnvironment.target_os` contains more info about OS.

### i have questions :
1) is `pr` allwayes between 0 to `nPr-1`?
2) what else wip could be? just local?
3) what is nPr and np and why they even exists when there is no usage.
4) `_dateparsefailure` not realy undeestandable.
5) why 443 outputs as http not https?
