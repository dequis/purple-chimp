# purple-chimp

![](chimp.png)

Work-in-progress Amazon Chime prpl (protocol plugin) for Pidgin/libpurple

VERY EXPERIMENTAL! Don't expect it to do anything useful yet.

Websocket code, purple3 compat, etc stolen from funyahoo plugin by eionrobb.

## How to set up

Add a new account to Pidgin.  The dropdown list should have a "Chimp" option.

Manual login instructions (TODO make this nicer):

1. Go to https://signin.id.ue1.app.chime.aws/
2. Log in normally
3. You should get redirected to a page that says "The address wasn't understood", that is normal
4. Look at the address bar of your browser
5. Copy the whole thing after "chime://sso_sessions?Token=", the long string starting with "ey"
6. Go back to pidgin, put your email as username and that long string as the password

### How to install on Windows ###

Download [libchimp.dll](http://dequis.org/libchimp.dll) and place into your `Program Files\Pidgin\plugins` folder.  (If you haven't used the Facebook, Skypeweb or Hangouts plugin before you'll also need to download  [libjson-glib-1.0.dll](https://github.com/EionRobb/skype4pidgin/raw/master/skypeweb/libjson-glib-1.0.dll) and place that into `Program Files\Pidgin` - not the plugins folder.)

### How to compile for Linux ###
```
sudo apt-get install libpurple-dev libjson-glib-dev libglib2.0-dev git make;
git clone https://github.com/dequis/purple-chimp.git && cd purple-chimp;
make && sudo make install
```
### How to compile for windows ###
You probably don't want to do this, but follow [these instructions](https://developer.pidgin.im/wiki/BuildingWinPidgin) to build pidgin and get a working build environment, then adjust the first few lines of the makefile to match your paths (ignore pidgin3 stuff) and type `make` to get your dll. Good luck with that.

Just use the binaries instead.

### Why chimp?

I typoed the name once and I liked it so it stuck.

### License

GPLv3+ licenced

Logo based on https://openclipart.org/detail/235969/flat-monkey
