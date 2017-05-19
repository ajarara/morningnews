# Internet only TV best TV
But one thing that I miss is the convenience of turning on my TV and having it already set to a channel. I don't want to fumble around with different remotes at 7:00 in the morning, ideally I'd like to zombie-waltz over to the TV and just hit the power button.

# My setup
I've got the Roku 4, paired with Emby. On Emby I've got a local news channel m3u hooked up. The missing piece is to have this channel autoplay at a specific time.

So far, all I've got is the ability to get an API key. Emby is still sorting out the details of ACME registration with LetsEncrypt.

But I figured I'd put this stuff up anyway. One thing that I learned: Emby's wiki is currently outdated. I spent a couple of hours trying to figure out how to do Auth until I had the bright idea of looking at the requests made by the web interface. Emulating those worked great, the first time.

