# RC5
RC5 algorithm in Ruby

In cryptography, RC5 is a symmetric-key block cipher notable for its simplicity.
RC5 has a variable block size (32, 64 or 128 bits). You can change it with W constant.

The following variable names are used:
<ul>
<li>b - The length of the key in bytes</li>
<li>key - The key, considered as an array of bytes (using 0-based indexing) </li>
<li>W - The length of a word in bits. Typical values of this in RC5 are 16, 32, and 64. Note that a "block" is two words long </li>
<li>R - The number of rounds to use when encrypting data</li>
<li>S - The expanded list of words derived from the key, of length 2(r+1), with each element being a word </li>
<li>L - A convenience to encapsulate K as an array of word-sized values rather than byte-sized </li>
</ul>

Algorithm was taken from <a href = 'https://github.com/tbb/pyRC5/blob/master/RC5.py'> github project </a> and rebuilt into Ruby.
