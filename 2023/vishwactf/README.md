# VishwaCTF 2023

### We Go JIM

We are given 4 wav files, and description says to arrange them to get message. Using Audacity we can get the spectrograms for them. Arranging 10 kg up above and 10 kg down below gives text “Gosqrd”. Similarly for 20 kg we get “Romnz”. Seems to be some simple encryption. Caesar shifting them separately gives “Light Weight”, one of the dialogues of Ronnie Coleman!

![1.png](/home/arrow/Desktop/projects/github/ctf-writeups/2023/vishwactf/images/1.png)

![2.png](/home/arrow/Desktop/projects/github/ctf-writeups/2023/vishwactf/images/2.png)

Flag: `VishwaCTF{Light_Weight}`



### Nice Guys Finish Last

Description mentions “rules”, check discord rules channels, flag found.

Flag: `VishwaCTF{g3n3r1c_d1sc0rd_fl4g}`



### Welcome to VISHWACTF'23!

Description gives flag directly.

Flag: `VishwaCTF{w3_ar3_an0nym0u5_w3_4r3_l3g1on_w3_d0_not_f0rg1v3_w3_do_not_f0rg3t}`



### I LOVE YOU

Description mentions “sound very deep”. DeepSound software is used to extract secret exe file from the audio file. The exe file on running is simple OSINT, it asks last words to the daughter of the narrator, which we know it is Tony Stark from the quote at the beginning of audio file. The last words are “I_LOVE_YOU_3000”. After this it gives flag format as {friend first name_first appearance}, which with little googling we get the flag.

Flag: `VishwaCTF{James_2008}`



### Privacy Breach

In the description, “offenders” and “plaintext” is capitalised. On googling “offenders plaintext”, we get https://plaintextoffenders.com/ . In the offenders list, trying the last offender gives the correct flag.

Flag: `VishwaCTF{napcosecurity.com}`



### Blockblaster

The audio dialogue is from the movie “Zameen”, in the TOI movie details page for zameen, we see 2 comments related to the challenge. The first one gives the flag format and says they like all movies of same director. The second one says it collected 229 cr less domestically. With some googling we get zameen domestic box office is 11 cr and the movie simmba by same director has domestic box office 240 cr, which matches the numbers.

Flag: `VishwaCTF{28122018_simmba}`



### Guatemala

- Running [exiftool](https://exiftool.org/) on the given `AV.gif` shows a comment => `dmlzaHdhQ1RGe3ByMDczYzdfdXJfM1gxRn0=`
- Decoding the comment using [base64](https://www.base64decode.org/) gives the flag `vishwaCTF{pr073c7_ur_3X1F}`



### Can you see me?

- Running [foremost](https://foremost.sourceforge.net/)/[binwalk](https://github.com/ReFirmLabs/binwalk) on the image gives a `.zip` file, from which `hereissomething.wav` is extracted.
- Opening the wav file in [sonic visualiser](https://www.sonicvisualiser.org/) and viewing the spectrogram gives the flag => `vishwaCTF{n0w_y0u_533_m3}`



### The Sender Conundrum

- Given an encrypted zip file with the flag and `TheEmail.eml`, we analyze the eml file using a tool like [eml-analyzer](https://eml-analyzer.herokuapp.com)
- The content of the e-mail is a riddle:
    ```html
    <p></p>Hello Marcus Cooper,<br>
    You are one step behind from finding your flag. <br>
    Here is a Riddle: <br>
    I am a noun and not a verb or an adverb.<br>
    I am given to you at birth and never taken away,<br>
    You keep me until you die, come what may.<br>
    What am I?<br>
    ```
    The answer to this riddle is simple enough, a name.
- In the headers of the mail we see that it is sent by `noreply@anonymousemail.me` but the `return-path` is `BrandonLee@anonymousemail.me`
- Using `BrandonLee` as the password for the zipfile, we extract `flag.txt` and view it to get the flag => `vishwaCTF{1d3n7i7y_7h3f7_is_n0t_4_j0k3}`



### Mystery of Oakville Town

- We are given an sqlite database file, an image, and instructions to find the first name and last name of the thief as well as the town he escaped to.
- Opening the image, we see that the license plate is `WB 0420`, which when checked in the database using a tool like [db browser](https://sqlitebrowser.org/), belongs to `Johannes True`, so this is a red herring.
- However, at the bottom right of the image, we also see the exact date-timestamp of picture.
- Checking the database for the same, we see that a vehicle with license plate number `OV-007` was heading to `SW` (Springwood) at that exact time. The vehicle belongs to one `Wellington East`.
- Putting these together, we get `VishwaCTF{WellingtonEastSpringwood}` as the flag



### Fr1endship Forever

- In the description, the creator of the challenge talks about his Fr1end James, so searching for the username `Fr1endJames` using [sherlock](https://github.com/sherlock-project/sherlock), we get a twitter account [@Fr1endJames](https://twitter.com/Fr1endJames)
- We see some talk about an Endsem last minute project, source control and a deleted comment.
- Checking on [Wayback Machine](web.archive.org), we find 2 snapshots for the account, with one having the phrase "Endsem last minute project" as `Endsem_Last_Minute-Project`.
- Searching for this on GitHub, we get [Endsem_Last_Minute-Project](https://github.com/Your-James/Endsem_Last_Minute-Project)
- There is a [Flag](https://github.com/Your-James/Endsem_Last_Minute-Project/blob/main/Flag) file but this is a red herring, no flag there. Going through commit history, we find the find the flag in [suggester.cpp](https://github.com/Your-James/Endsem_Last_Minute-Project/commit/fe599443374ecc8026da74872cc22ac62e1c55e6) => `VishwaCTF{LbjtQY_449yfcD}`



### The Indecipherable Cipher

- Challenge name (The Indecipherable Cipher) and description (Mr. Kasiski) point to [Vigenere cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher).
- The ciphertext also has numbers so the alphabet is `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789` rather than just `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
- Now we can simply brute-force using a site like [dcode.fr](https://www.dcode.fr/vigenere-cipher)
- We get plaintext `friedrichwilhelmkasiskiwastheonewhodesignedtheaaakasiskiexaminationtodecodevignerecipher` decoded with key `EMINENCESHA`
- The flag is simply `VishwaCTF{friedrichwilhelmkasiskiwastheonewhodesignedtheaaakasiskiexaminationtodecodevignerecipher}`
