sansj
=====

Simple Authoritative Name Server - Java

## Features

- Standalone and lightweight, no dependencies except Java 1.7+
- JSON Based Simple DNS Configuration
- Supports : A, CNAME, MX, NS, TXT Queries
- Only Authoritive DNS, No forwarding
- Auto reload of configuration files
- Per file Zone definitions




## Configuration

	{
	    "zone":"aniljava.com", 
	    "data":{	        
	        "mx":[[300, 30 , "aspmx.l.google.com."],[300, 40, "aspmx2.googlemail.com."]],
	        
	        "a" :{
	            "aniljava.com":[[6522,"127.0.0.1"]],
	            "www.aniljava.com":[[300,"184.154.161.21"],[600,"184.154.161.22"]],
	            "*":[[300,"184.154.161.21"]]
	        },
	        
	        "c" :{
	            "test.aniljava.com":"aniljava.com."
	        },
	        
	        "ns":[[163255,"ns1.godaddy.com."],[163255,"ns2.godaddy.com."]]
	        	        
	    }
	}
	

##Running

    # sudo java -jar sansj-1.0RC1-jar-with-dependencies.jar <config> <reloadInterval> <port>
    ## DEFAULT IS
    # sudo java -jar sansj-1.0RC1-jar-with-dependencies.jar config 300000 53