# PadOrAck

Pad(ding)Or(acle)A(tta)ck

This script was made for a CTF that I went through. I've never done a padding
oracle attack before and felt it would be more fun (and a better learning 
experience) if I were to manually implement my own script to perform the 
attack rather than using something someone else made.

## Usage
    
    ./PadOrAck -u "http://example.com/oracle?post=" -e "PaddingException" -c "base64 cipher"
    

## Notes

This script is not as configurable as most off the shelf scripts are for this.
This script was made specifically for a certain CTF. Anyone who has completed 
that CTF should be able to know which it is based off the base64 function. I've
tried to keep all references to that CTF hidden so that this script isn't used
by anyone else in said CTF. I feel it is more beneficial for anyone completing
the CTF to read about the padding oracle attack and implement it themselves so
they can understand exactly how to do it, rather than use a script someone else 
made. It can be a really useful exercise.
