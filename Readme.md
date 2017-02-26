# SIDH-RSA-AES128-GCM-SHA256
BKPCTF 2017 - Crypto, 600 points  
Author: Colin Stanfill  
Thanks: Allan Wirth (challenge idea), George Silvis III (Support), Microsoft
Research (SIDH library)

## Challenge description:
We kind of lost the flag to this challenge... I think someone submitted it on
the old version of the site though, maybe you can help us find it again?

`https://<server url>`

`<file download of TLS packet capture>`

## Challenge setup:
The server in the challenge description served static html over https with a
special patch[1][2] to support "Super-singular Isogeny Diffie-Hellman Key
Exchange" as an intial key exchange method (in TLSv1.2 only). ALL other
ciphersuites and TLS versions were disabled, so any normal browser that
connected to the site would fail to finish the SSL handshake. Plain HTTP was not
enabled (plaintext requests at port 443 would display an error page, which we
couldn't configure out of nginx in time).

However, if an application was compiled to support SIDH as a key exchange
method, the server would provide a valid, authenticated
[LetsEncrypt certificate](https://crt.sh/?id=96445460) for its domain.

The packet capture contained https traffic to the server using the ciphersuite
in the challenge name. The https session consisted of a single session in which
a user POSTed a flag to a submission form on the site.

## Vulnerability:
Server reuses private+public key in SSL key exchange across all connections,
which allows recovery of past SSL session keys, including the one in the pcap.

[Source for attack (Section 3)](https://eprint.iacr.org/2016/859.pdf)  
Allan first heard of this attack at a
[Real World Crypto](https://www.realworldcrypto.com/rwc2017) talk given by
Michael Naehrig in 2017, titled "Supersingular Isogeny Diffie-Hellman". Slides
for that talk can be found
[here](https://www.cs.bris.ac.uk/Research/CryptographySecurity/RWC/2017/michael.naehrig.pdf)

### Brief but math-heavy summary:
Alice's private key is a number `n_A`. Bob's public key a pair of elliptic
curve points `P_B`, `Q_B` such that `[2^372]P_B = [2^372]Q_B = 0`. The shared
secret is calculated by Alice based on the value `Q_B + [n_A]P_B`.

Bob calculates his shared secret honestly but sends Alice the public key
`Q_B, P_B + [2^371]Q_B`, so Alice will calculate her shared secret based on
` Q_B + [n_A]P_B + [2^371 * n_A]Q_B ` instead. If `n_A` is even, then the
factor on the second `Q_B` will be divisible by `2^372` and the term will
multiply to zero, giving her the same shared secret as Bob. Otherwise, they
will get different shared secrets.

Let us assume that Alice's `n_A` was odd, so the low bit is 1 (in practice it
is always 0, but whatever). Now we can repeat the process, but with Bob sending
`Q_B - [2^370]Q_B, P_B + [2^370]Q_B`.
Alice calculates `Q_B - [2^370]Q_B + [n_A]P_B + [2^370 * n_A]Q_B`.
We know her low bit is one, so the `-[2^370]Q_B` term will cancel out with one
of the `[2^370]Q_B`s leaving `Q_B + [n_A]P_B + [2^370 * (n_A - 1)]Q_B`, where
`n_A - 1` is even. So now the rightmost `Q_B` term will vanish to zero (giving
Alice the same shared secret as Bob) if and only if `n_A - 1` is divisible by 4;
that is, if the second-lowest bit of `n_A` is 0.

This is the procedure: lower the exponent of the rightmost `Q_B` term depending
on the bit we're trying to find out, and cancel out the bits we know about by
subtracting them from the leftmost `Q_B` term. Repeat until we have almost all
of the bits of `n_A` (the last bits are hard to detect for mechanical reasons).
We have now effectively recovered Alice's private key!

## Intended solution:
Googling the challenge name should lead teams to the OpenSSL `1.0.2g`[1] patch
which enables support of SIDH key exchange. Once they downloaded and patched
OpenSSL, they should be able to reach the site using openssl `s_client`, or
anything else linked against OpenSSL. Brownie points if you managed to compile
your actual browser to be able to view the site, although it's not necessary.

There's nothing useful on the site; all the pages are static html and contain
nothing interesting. We just put a POST form asking for flags on the site so
that people would be pretty sure that the packet capture contained the flag
itself.

However, the site itself is good as an SSL key exchange success oracle. By
negotiating SSL using specific faulty key exchange parameters and checking for
garbled data, it is possible to recover one bit of the server's private key per
connection. See the paper linked above for details, or read the code in this
repo. Because the site's server reuses the private key every time, doing this
~372 times allows you to recover the private key fully, modulo one or two high
bits [3].

The ultimate goal is to decrypt the pcap using the server private key that was
extracted with the oracle attack; once you know that, you can combine that with
the client public key from that session to generate the SSL master key and from
there decrypt all data in the pcap. Then you see the client says this to the
server:

     POST /submit.html HTTP/1.1
     Content-Length: ...
     Content-Type: application/x-www-form-urlencoded

     flag=...

And you're done! No sweat (?)

## Thought process we were looking for:
"OK so the site contents seem to be useless. We're using TLS, so it's probably
not a protocol problem. This is crypto not pwning. SIDH is the only thing weird
about the crypto setup and it's in the name+url... are there any known
vulnerabilities in, uh, SIDH key exchange?"

Yes, there are!  
Searching for things like "supersingular isogeny diffie hellman attack" quickly
find [a paper](https://eprint.iacr.org/2016/859.pdf) which lists a few ways for
the protocol to be softened:

  1. ADAPTIVE ATTACK  
  In this section, we will assume that Alice is using a static key (a1, a2), and
  that a dishonest user is playing the role of Bob and trying to learn her key

  2. SOLVING THE ISOGENY PROBLEM WHEN THE ENDOMORPHISM RING IS KNOWN  
  In this section we additionally suppose that we know (or can compute) the
  endomorphism rings End(E) and End(EA) [...]

  3. ISOGENY HIDDEN NUMBER PROBLEM  
  In this section we present an algorithm that takes partial information about
  the shared j-invariant j(EAB) of Alice and Bob, and recovers the entire
  j-invariant, i.e. their shared key. This algorithm can therefore be used as a
  tool to obtain the shared key from a side-channel attack and to prove a bit
  security result

"Number 2 seems really really mathy, and they're using the same curve as that
published Microsoft Research patch, so it's unlikely to be vulnerable to
something that depends mostly on the curve E. Hopefully it's not that!"  
(it's not!)

"Number 3... oh god, they don't want us to do a side channel attack on
_post-quantum ECC_, do they??"  
(we don't)

"Number 1... well we can at least check easily if Alice (server) is using a
static private key by seeing if the SSL public key handshake is always the same"  
(it is!)

"OK so if we can find the private key (the attack lets us do that), we should
be able to figure out the SSL master secret and decrypt EVERYTHING in the pcap!
Let's see what's in there!"

And then you bang your head against elliptic curve math (in C) for like 18 hours.

## Problems with this challenge
No teams solved this challenge at BKP2017, which is unfortunate. Here's some
problems we identified with the challenge when we ran it:

* It's **very** hard. You have to find a vulnerability in an obscure protocol on
elliptic curves, then *implement* it, which is highly nontrivial. Once you've
done that, you have to then get something to decrypt the pcap which basically
involves manually patching the pcap to trick `wireshark` into thinking it's
something ECDHE-RSA-AES128-GCM-HMAC so it can decrypt the block cipher
correctly.
* Implementing also takes a while. A team we contacted figured out the
vulnerability with 9 hours left in the CTF and did not think they would be able
to complete the attack in time (probably true). This was a launch challenge for
our 48 hour CTF for a reason.
* 600 points is our traditional "unbounded difficulty" point value, but it was
a step above the previous hardest crypto challenges. Another challenge this year
ended up being 750 points with several solves, so based on that point value this
could have been more like 900 or even 1000 (our point values this year were all
over the place anyway).
* At least one team determined that it was so hard that probably nobody would
solve it, so it was a bad time investment to try very much at it. This turned
out to be the correct strategy, which is totally lame.
* Finding the vulnerability proved to be more subtle than expected. Several
high-level teams we expected to have a real shot at solving it didn't manage to
find the paper we pulled the attack from. They may have assumed that the lack of
any server code provided meant they could assume the server wasn't doing
anything especially unusual (except for providing a bizarre ciphersuite).
* If we could run this challenge again, we would probably include several ssl
sessions in the pcap to lead people down the 'reused key exchange' route, or
maybe even make the key reuse obvious from the description. Another possibility
would be to have the teams implement a custom protocl instead of using SSL,
which would encourage them to notice the reused server public key.

## Our solution
See code in this repo.  We used:

* the standalone SIDH library[4] from the same Microsoft Research group as the
openSSL patch
* the OpenSSL patch[1]
* `tshark`
* `python` + `sh` to drive everything

First, when developing, we simulated this attack entirely locally using the SIDH
library[4]. The testing code is in `local_attack.c`; some of it made it into our
final attack.

For the actual full attack solution, we patched openssl to support SIDH in a
client binary, using `s_client` to connect to the server. Then we added some
code to optionally modify the public key just before it goes out on the wire
based global variables that were set by new flags to `s_client`. If the
modifications to the public key do not change the shared secret calculated by
the server, then `s_client` will succesfully handshakel; otherwise it will fail
(it forgets the modified public key when it sends it, so it does shared secret
 calculations based on the unmodified public key, just like the attack in the
 paper).

This was driven by a `python` script that did the logic of keeping track of
which bits had been determined and checked for inconsistencies along the way.
While checking for inconsistencies (and thus doing twice as many queries as is
        necessary), this took about 5 minutes locally and 12 minutes against the
server at the beginning of the ctf. While preparing this writeup, it took more
like 30 minutes to run against the production ctf server, for unknown reasons.
Solution is still feasible in 15 minutes, almost all network time, by disabling
the consistency checks.

After we had the private key from the server, we scripted `tshark` to extract
the client public key from the session in the pcap, and used that + the
standalone SIDH binary to compute the ssl pre-master key from the pcap.

Unfortunately, `tshark` needs the actual master key to decrypt the session, so
we wrote a quick `python` script to go from pre-master to master under our
ciphersuite, feeding it the client + server randoms as well, which were also
found by `tshark`.

Finally, we have the master secret and `tshark` can decrypt the session! But we
couldn't figure out how to get it out of `tshark`'s normal interface so we just
had it debug log to a file and then parsed it with a hacky `python` script. You
can also just open the pcap in `wireshark` and poke around the interface until
you find the decrypted data.

## Files
* `attack.sh`                 - Full attack driver
* `util/attack`               - Uses openssl oracle to determine server private
* `util/openssl`              - Precompiled openssl oracle
* `util/extract`              - Precompiled SIDH/extract.c
* `util/generate_master_key`  - Premaster, client, server rand => master secret
* `util/ex.lua`               - Convenience `tshark` plugin from the internet
* `SIDH/`                     - Microsoft Research library
* `SIDH/local_attack.c`       - local (serverless) PoC - not needed for attack
* `SIDH/extract.c`            - Client pubic, server private => premaster
* `patches/sidh-1.0.2k.patch` - Patch openssl `1.0.2k` to support SIDH
* `patches/server.patch`      - Patch server further to reuse private SIDH key
* `patches/client.patch`      - Patch client further, to act as SIDH oracle
* `data/accesslog.pcap`       - Packet capture from competition
* `conf/nginx.conf`           - For running nginx server
* `Dockerfile`                - For running nginx server, expects cert in data/
* `site/`                     - Static html served by nginx server

---
[1] `https://www.microsoft.com/en-us/download/details.aspx?id=54053`  
[2] We forward-ported the patch to work with `OpenSSL 1.0.2k` and remade the
patches so that we hopefully wouldn't be vulnerable to any nasty old OpenSSL
bugs on the server. The updated patch is in the patches/ directory.  
[3] It turns out the top bit or so of the private key doesn't seem to really
change the shared secret calculated. So you can't fully determine the private
key, but you can determine it enough to get the shared secret. And you can
always brute force 1-4 bits trivially offline if it's a problem. We deliberately
left most of the high bits off of our server private key so that solvers that
ran into trouble near the end would by default get the right key if they gave up
around bit 370.  
[4] `https://www.microsoft.com/en-us/research/project/sidh-library/`
