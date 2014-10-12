skewprint
=========

Skewprint aims to be an industrial strength tool for identifying devices from across the internet by their clock skew. Research has shown that no two ordinary computers keep time at exactly the same rate. Skewprint will be able exploit these minute differences to uniquely identify devices from across the internet by repeatedly asking the device for the time. After a suitably long period of data collection, Skewprint will be able to estimate how much faster or slower the remote device's clock is ticking compared to the clock Skewprint is running on. This information can be used to identify the remote device at a later time even when the source ip address or other typical identifying information is not present. All Skewprint will need is the time the remote device recieved the time request packet, and the time the response arrived back.

For more information read:

Kohno, Tadayoshi, Andre Broido, and Kimberly C. Claffy. "Remote physical device fingerprinting." Dependable and Secure Computing, IEEE Transactions on 2.2 (2005): 93-108.

Murdoch, Steven J. "Hot or not: Revealing hidden services by their clock skew." Proceedings of the 13th ACM conference on Computer and communications security. ACM, 2006.

Zander, Sebastian, and Steven J. Murdoch. "An Improved Clock-skew Measurement Technique for Revealing Hidden Services." USENIX Security Symposium. 2008.

Installing
==========

THIS SOFTWARE IS A WORK IN PROGRESS. Don't bother trying to use it if you don't want to implement it yourself.

Just copy clockskew.py to a convenient location. To test it is working, navigate to where you installed it in a command prompt and run:

	python clockskew.py https://www.google.com/

Skewprint needs to be run as root or Administrator.
