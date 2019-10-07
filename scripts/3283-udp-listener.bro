module DoS; 

redef enum Notice::Type += {
	## Indicates a high likelyhood of successful shellshock exploitation.
       	AppleRDPListener, 
};

export { 
	global net_assistant = 3283/udp ; 
} 


hook Notice::policy(n: Notice::Info)
{
  if ( n$note == DoS::AppleRDPListener)
        {
            add n$actions[Notice::ACTION_EMAIL ];
        }
}

event udp_session_done(c : connection)
{

        local dst = c$id$resp_h;
        local dport = c$id$resp_p ;

        if (dport == net_assistant && dst in Site::local_nets && /d|D/ in c$history )
	{ 



		local  _msg = fmt ("APPL RDP 3283/udp Listener Seen: %s, %s, %s, %s, %s, %s, %s", c$id, c$orig, c$resp, c$start_time, c$duration, c$history, c$uid) ; 

		NOTICE([$note=DoS::AppleRDPListener, $src=dst, $msg=_msg, $identifier=cat(dst), $suppress_for=1 hrs ]);
	} 
}
	

##[id=[orig_h=76.103.238.248, orig_p=3283/udp, resp_h=128.3.124.59, resp_p=3283/udp], orig=[size=9008, state=1, num_pkts=111, num_bytes_ip=12116, flow_label=0, l2_addr=00:d0:f6:f4:15:2b], resp=[size=18321, state=1, num_pkts=117, num_bytes_ip=21597, flow_label=0, l2_addr=a8:d0:e5:e1:a9:52], start_time=1561047843.233615, duration=2117.734613, service={\x0a\x0a}, history=Dd, uid=C2dIha4QhVJe7xk4jh
