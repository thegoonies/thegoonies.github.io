
---
layout: post
title: ASIS CTF 2020 - Adventure [misc, forensics]
author: jeremy
tags: [ctf, asis, forensics]
---

 * Competition: [https://asisctf.com/challenges](https://asisctf.com/challenges)
 * Challenge Name: adventure
 * Type: Misc, Forensics
 * Points: 169 pts
 * Description: Time plays a role in almost every decision. And some decisions define your attitude about time.
Can you  [README.txt](http://66.172.11.212:1337/large.tar)? It's time for a new adventure!
Note: Slow-download is international and part of the task.


For this masochists task, we are given a URL to a gigantic file that downloads slowly. The description says that it's part of the tasks. This hints that we might need to download interesting parts of the file by chunks using `Range`. This is confirmed by the `Accept-Ranges` response header:

```http
$ curl --head http://66.172.11.212:1337/large.tar
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 06 Jul 2020 03:49:15 GMT
Content-Type: application/octet-stream
Content-Length: 4919797760
Last-Modified: Sat, 04 Jul 2020 09:27:11 GMT
Connection: keep-alive
ETag: "5f004b6f-1253e2800"
Accept-Ranges: bytes
```

Let's look at the beginning of the file.

```
$ curl -r 0-10000 http://66.172.11.212:1337/large.tar -o - | strings
[...]
Hello, Adventurer!
Here's your quest. Look for 38.html in 14.zip.
Good luck.
[...]
```

This information hints that the big TAR file contains several ZIP files, each of which would contain several HTML files. We need to find the correct offset in the TAR to download 14.zip. We used the following script to build an index of the start and end offsets of all ZIP files in the TAR, skipping non-ZIP files:

```python
file_offsets = {}
current_offset = 0
SESS = requests.Session()

# This will iterate through all files within the TAR by looking at the file sizes and skipping chunks.
# If the file is a ZIP, then store the 'start' and 'start + file_size' offsets.
while True:
	chunk = SESS.get("http://66.172.11.212:1337/large.tar", headers={"Range": "bytes={}-{}".format(current_offset, current_offset+2048)}).content

	i = 0
	# it seems like all files in the TAR have a 644 permission.
	# We can use that to identify where the file metadata starts.
	# 100 bytes before that is the file name.

	if b'0000644' not in chunk:
		break # we have reached the end

	while chunk[i+100:i+107] != b'0000644':
		i += 1

	current_offset += i
	chunk = chunk[i:]
	# our chunk now starts at the file name.

	hexdump(chunk[:160])

	metadata = list(filter(None, chunk[:32*16].split(b'\x00')))
	file_name = metadata[0]
	file_size = int(metadata[4], 8)

	if file_name.endswith(b'.zip'):
		current_offset += chunk.find(b'PK')
		zip_nb = int(file_name[0:2])
		file_offsets[zip_nb] = (file_name, current_offset, current_offset + file_size)
		print(zip_nb, file_name, file_size)

	else:
		print("Not adding", file_name)


	current_offset += file_size

print(file_offsets)
```

This yields a dictionary containing all offsets. It turns out that each ZIP is around 8Mb in size, still too big to download considering the slow download speed. We will have to download the headers of each ZIP, and iterate through the files within each ZIP.

Once we find the correct offset of the HTML file we're interested in, we download a range of bytes from `start_of_file` to `start_of_file + file_compressed_size + 64`. This will result in a corrupted ZIP, but we can still extract it using 7Zip (it might be possible to fix the ZIP to extract it properly, but that worked and we couldn't be bothered).

We used the following script.

```python
import requests, sys, os, glob

zip_offsets = {0: (b'00.zip', 952114688, 960164083), 1: (b'01.zip', 960164864, 968215002), 2: (b'02.zip', 968215552, 976267211), 3: (b'03.zip', 976267776, 984319480), 4: (b'04.zip', 984320000, 992371092), 5: (b'05.zip', 992371712, 1000422660), 6: (b'06.zip', 1000423424, 1008474007), 7: (b'07.zip', 1008474624, 1016525526), 8: (b'08.zip', 1016526336, 1024577060), 9: (b'09.zip', 1024578048, 1032628130), 10: (b'10.zip', 1292676608, 1300728512), 11: (b'11.zip', 1300729344, 1308780086), 12: (b'12.zip', 1308781056, 1316831919), 13: (b'13.zip', 1316832768, 1324884862), 14: (b'14.zip', 1324885504, 1332936833), 15: (b'15.zip', 1332937728, 1340988857), 16: (b'16.zip', 1340989440, 1349039050), 17: (b'17.zip', 1349039616, 1357089517), 18: (b'18.zip', 1357090304, 1365142595), 19: (b'19.zip', 1365143552, 1373195111), 20: (b'20.zip', 1633243648, 1641293567), 21: (b'21.zip', 1641294336, 1649344690), 22: (b'22.zip', 1649345536, 1657397491), 23: (b'23.zip', 1657398272, 1665448389), 24: (b'24.zip', 1665448960, 1673498303), 25: (b'25.zip', 1673499136, 1681549265), 26: (b'26.zip', 1681549824, 1689600833), 27: (b'27.zip', 1689601536, 1697651730), 28: (b'28.zip', 1697652736, 1705704865), 29: (b'29.zip', 1705705472, 1713755848), 30: (b'30.zip', 1973804544, 1981855280), 31: (b'31.zip', 1981856256, 1989906786), 32: (b'32.zip', 1989907456, 1997957277), 33: (b'33.zip', 1997958144, 2006009008), 34: (b'34.zip', 2006009856, 2014061518), 35: (b'35.zip', 2014062080, 2022113177), 36: (b'36.zip', 2022113792, 2030167410), 37: (b'37.zip', 2030168064, 2038218676), 38: (b'38.zip', 2038219264, 2046271085), 39: (b'39.zip', 2046272000, 2054324991), 40: (b'40.zip', 2054325760, 2062376298), 41: (b'41.zip', 2062376960, 2070427472), 42: (b'42.zip', 2330476032, 2338527958), 43: (b'43.zip', 2338528768, 2346581026), 44: (b'44.zip', 2346582016, 2354633929), 45: (b'45.zip', 2354634752, 2362683979), 46: (b'46.zip', 2362684928, 2370736220), 47: (b'47.zip', 2370737152, 2378788090), 48: (b'48.zip', 2378788864, 2386840079), 49: (b'49.zip', 2386841088, 2394892339), 50: (b'50.zip', 3477024768, 3485075715), 51: (b'51.zip', 3485076480, 3493126300), 52: (b'52.zip', 3623151104, 3631202624), 53: (b'53.zip', 3631203328, 3639254048), 54: (b'54.zip', 3639255040, 3647304776), 55: (b'55.zip', 3647305728, 3655358340), 56: (b'56.zip', 3655358976, 3663410448), 57: (b'57.zip', 3663411200, 3671459818), 58: (b'58.zip', 3671460352, 3679512310), 59: (b'59.zip', 3679513088, 3687563695), 60: (b'60.zip', 3687564288, 3695615428), 61: (b'61.zip', 3695616000, 3703666420), 62: (b'62.zip', 3703667200, 3711717964), 63: (b'63.zip', 3711718912, 3719771189), 64: (b'64.zip', 3719772160, 3727821910), 65: (b'65.zip', 3727822848, 3735874098), 66: (b'66.zip', 3735875072, 3743924641), 67: (b'67.zip', 3743925248, 3751975683), 68: (b'68.zip', 3751976448, 3760028069), 69: (b'69.zip', 3760028672, 3768079578), 70: (b'70.zip', 3898104320, 3906156153), 71: (b'71.zip', 3906157056, 3914207516), 72: (b'72.zip', 3914208256, 3922258897), 73: (b'73.zip', 3922259456, 3930311209), 74: (b'74.zip', 3930312192, 3938362949), 75: (b'75.zip', 4068387840, 4076438195), 76: (b'76.zip', 4076439040, 4084490885), 77: (b'77.zip', 4084491776, 4092542117), 78: (b'78.zip', 4092542976, 4100594081), 79: (b'79.zip', 4100594688, 4108644547), 80: (b'80.zip', 4108645376, 4116696839), 81: (b'81.zip', 4246721536, 4254772858), 82: (b'82.zip', 4254773760, 4262825317), 83: (b'83.zip', 4262825984, 4270876325), 84: (b'84.zip', 4270877184, 4278927213), 85: (b'85.zip', 4278927872, 4286977929), 86: (b'86.zip', 4286978560, 4295029320), 87: (b'87.zip', 4295030272, 4303080395), 88: (b'88.zip', 4303080960, 4311132747), 89: (b'89.zip', 4311133696, 4319184711), 90: (b'90.zip', 4449210368, 4457260440), 91: (b'91.zip', 4457261056, 4465310933), 92: (b'92.zip', 4465311744, 4473362932), 93: (b'93.zip', 4473363456, 4481414993), 94: (b'94.zip', 4481415680, 4489467058), 95: (b'95.zip', 4489467904, 4497517791), 96: (b'96.zip', 4497518592, 4505569673), 97: (b'97.zip', 4635594240, 4643644378), 98: (b'98.zip', 4643644928, 4651695579), 99: (b'99.zip', 4781720064, 4789770351)}

SESS = requests.Session()

def dl_file_from_offset(off, sz):
	
	zf = f"zip_{ZIP_NB}_file_{FILE_NB}.zip"

	print(f"Saving file {zf} ...")

	off_end = off+sz+64
	data = SESS.get("http://66.172.11.212:1337/large.tar", headers={"Range": "bytes={}-{}".format(off, off_end)}).content
	
	with open(zf, 'wb') as f:
		f.write(data)
		f.close()

		# Unzip will fail as the ZIP will be corrupted.
		# 7zip seems to do the job.
		os.system("7z -bso2 -y x %s 2>/dev/null" % zf)
		os.rename("%02d.html" % FILE_NB, "letters/%02d.html" % LETTER_NB)
		print(f"File for letter {LETTER_NB} saved.")
		sys.exit()

def iterate_through_zip(off):

	chunk = SESS.get("http://66.172.11.212:1337/large.tar", headers={"Range": "bytes={}-{}".format(off, off+200)}).content
	
	compressed_sz = int.from_bytes(chunk[18:22], byteorder='little')
	uncompressed_sz = int.from_bytes(chunk[22:26], byteorder='little')
	fn_len = int.from_bytes(chunk[26:28], byteorder='little')
	fn = chunk[30:30+fn_len]

	file_start = 30+fn_len+28
	print(fn, compressed_sz, uncompressed_sz, fn_len)

	if fn == FILE_NAME:
		# We have iterated in the ZIP all the way to the file we want.
		# We can download ZIPPED contents of this file with its offsets.
		dl_file_from_offset(off, compressed_sz)
	
	next_offset = off + file_start + compressed_sz

	return next_offset


if __name__ == '__main__':

	ZIP_NB = int(sys.argv[1])
	FILE_NB = int(sys.argv[2])
	FILE_NAME = b'%02d.html' % FILE_NB
	LETTER_NB = max([int(_.split("/")[1].split('.')[0]) for _ in glob.glob("letters/*.html")]) + 1

	off = zip_offsets[ZIP_NB][1]

	while off is not None:
		off = iterate_through_zip(off)
		print("Next offset:", off)

```

Now, by running this script and specifying the ZIP number and the HTML number (`14 38`), we could download and extract the relevant file.

The file contained some obfuscated JS (JSFuck), but displayed the first letter of the flag 'A', and the following information: `next stop: 14.html in 05.zip`.

We repeated the operation with the new numbers, which yielded the following letter, and so on until we got all the letters.

`ASIS{byte_Range_d0nt_pl4y_with_m3}`

```