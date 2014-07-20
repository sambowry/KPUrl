KPUrl
=====

Experimental URL Protocol handler plugin for KeePass >= 2.27 on Windows

The plugin 

- registers enabled Custom Overrides URI Schemes (Tools/Options/URL Overrides)
  into HKCU/Software/Classes at Keepass starting. It allows you to start/open
  an URL recorded in an entry string field outside of Keepass in Windows.
  
- extends KeePass with {PASSWORD:text} placeholder for password literals
  embedded directly into strings. Password hide/reveal "eye" button will be
  shown in KPEnchancedEntryView if you include a comment:
  
    "ilo://Administrator:{PASSWORD:text}{C:{PASSWORD}@10.11.12.13/"
    
- extends KeePass with an "eval" like function. If a string field start
  with "=" the field will replaced by the compiled value of the field.
  (Far from perfect, needs complete refresh of the entry view.)

  