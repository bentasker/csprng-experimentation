ChaCha20 Cryptographically Secure Random Number Generator Implementation
==========================================================================


Firstly, *DO NOT* use this for anything important.

This was created just to allow me to play around with building a CSPRNG incorporating various techniques - the aim was to then look at re-building it in LUA and maybe some other languages, but I haven't got that far yet.

* ChaCha20 based
* Uses [Fast Key Erasure](https://www.bentasker.co.uk/blog/software-development/689-writing-a-chacha20-based-csprng#fastkeyerasure)
* Has a ["prediction resistant" option](https://www.bentasker.co.uk/blog/software-development/689-writing-a-chacha20-based-csprng#predictionresistance)
* Implements [back-tracking protection](https://www.bentasker.co.uk/blog/software-development/689-writing-a-chacha20-based-csprng#backtracking)

Although the techniques are present, their actual effectiveness is likely to be substantially less than you'd hope for, as discussed in [this write up](https://www.bentasker.co.uk/blog/software-development/689-writing-a-chacha20-based-csprng)

Psuedo-Random bytes can be read from `/tmp/csprng` (configured by `pipe_name` at the top of the script).

The branch [`silly-backdoor`](https://github.com/bentasker/csprng-experimentation/tree/silly-backdoor) contains a modification to the PRNG which inserts a backdoor allowing an attacker to backtrack and calculate some of the bytes previously output - that branch also introduces a script `attack.py` to attack that backdoor. Writeup on that is [here](https://www.bentasker.co.uk/blog/software-development/689-writing-a-chacha20-based-csprng#backdoor).



----

### Random Data Source

By default, the script fetches random bytes from `/tmp/randentropy` which is a FIFO created by one of my other projects (not yet finished/published). This can be changed to `/dev/random` by editing `seed_source` at the top of the script. The reason this isn't `/dev/random` by default is it raises the likelihood you'll read this README and see the warning at the top.

----

### Randomness of Output

The output of this CSPRNG scores quite well in `ent`, `rngtest` and `dieharder`

    Entropy = 7.999980 bits per byte.

    Optimum compression would reduce the size
    of this 9956544 byte file by 0 percent.

    Chi square distribution for 9956544 samples is 277.10, and randomly
    would exceed this value 16.33 percent of the times.

    Arithmetic mean value of data bytes is 127.4985 (127.5 = random).
    Monte Carlo value for Pi is 3.141518985 (error 0.00 percent).
    Serial correlation coefficient is -0.000076 (totally uncorrelated = 0.0).


    rngtest 2-unofficial-mt.14
    Copyright (c) 2004 by Henrique de Moraes Holschuh
    This is free software; see the source for copying conditions.  There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    rngtest: starting FIPS tests...
    rngtest: entropy source exhausted!
    rngtest: bits received from input: 79652352
    rngtest: FIPS 140-2 successes: 3980
    rngtest: FIPS 140-2 failures: 2
    rngtest: FIPS 140-2(2001-10-10) Monobit: 0
    rngtest: FIPS 140-2(2001-10-10) Poker: 0
    rngtest: FIPS 140-2(2001-10-10) Runs: 0
    rngtest: FIPS 140-2(2001-10-10) Long run: 2
    rngtest: FIPS 140-2(2001-10-10) Continuous run: 0
    rngtest: input channel speed: (min=24.675; avg=1475.199; max=9536.743)Mibits/s
    rngtest: FIPS tests speed: (min=1.026; avg=16.291; max=16.746)Mibits/s
    rngtest: Program run time: 4718285 microseconds


This, of course, is very much indicative only and may be [entirely misleading](https://www.bentasker.co.uk/documentation/security/287-understanding-the-difficulty-of-assessing-entropy).

In fact, this outout was gathered whilst the script contained a [serious bug](https://www.bentasker.co.uk/blog/software-development/689-writing-a-chacha20-based-csprng#theresabuginmybackdoor) which resulted in the generating get being 16 binary 0's 50% of the time.



License
--------

This project is licensed under the [BSD 3 Clause License](https://opensource.org/licenses/BSD-3-Clause) and is Copyright (C) 2020 [Ben Tasker](https://www.bentasker.co.uk)
