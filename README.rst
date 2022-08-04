Framework implementing AES (advanced encryption standard) encryption. It can be used to encrypt and decrypt a file using 128, 192 or 256 bit AES.
During the encryption process, the UNIX timestamp is used as initial vector, so that the same file encrypted 2 times in row will result in a completely different encrypted file.


How to download and compile the code:
--------------------------------------

    git clone git@github.com:dubovsky14/AES.git

    cd AES

    mkdir bin

    cd bin

    cmake ../.

    make

How to use the framework:
--------------------------

How to encrypt:

    ./bin/main encrypt <input_file>  <output_file> <key>

How to decrypt:

    ./bin/main decrypt <input_file>  <output_file> <key>

The last argument, the key, is optional. If it's not provided through terminal, you will be asked to provide it at runtime.
The key will be converted into an array of chars (8 bit numbers).
Based on the length of the password, 128, 192 or 256 bit key will be used (a padding will be added to achieve the closest longer key length, if you use password more than 32 characters long, only leading 32 chars will be used).

The encrypted file has the following structure:

	Bytes 0-7: The length of the original file, saved as unsigned long int

	Bytes 8-23: Initial vector (by default it's unix time when the encryption was performed)

	Bytes 24-end of file: Encrypted content of the original file


Disclaimer:
------------

The framework is not meant to be an optimal framework for AES decryption/encryption,
especially not from the encryption speed point of view.
I'm aware of existence of math tricks which can speed up the algorithm significantly,
as well as the hardware instructions, which both allow for significantly higher speed than the one achieved by this framework (currently around 28 MB/s on my laptop using 128 bit key length).
I created the framework just for fun and to get a better understanding of how AES works and the math behind it.