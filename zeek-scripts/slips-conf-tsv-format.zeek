redef LogAscii::use_json=F;
# known-services will only consider local networks.
redef Site::local_nets += { 192.168.0.0/16 };
# zeek needs to know where maxmind db is. mmdb_dir should now be slips/modules/geoip
redef mmdb_dir = fmt("%s%s", rstrip(@DIR, "zeek-scripts/."), "/databases");