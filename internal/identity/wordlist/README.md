# BIP-39 English word list (vendored)

`english.txt` is the BIP-39 English word list, unmodified. OpenAIM's recovery phrase uses it (spec/wire.md §4.5).

| | |
|---|---|
| Source | https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt |
| Upstream commit | `ce1862ac6bcffa1dd20aad858380e51e66e949ea` (2014-02-07, the file's last change) |
| SHA-256 | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` |
| Words | 2048, sorted, unique, lowercase a–z, unique in their first four letters |

`internal/identity` checks the SHA-256 when it loads the list, so the file can't change silently.

## License

BIP-39 is published under the MIT license:

> Copyright (c) 2013 Marek Palatinus, Pavol Rusnak, Aaron Voisine, Sean Bowe
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
> documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
> rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
> persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
> Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
> WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
> COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
