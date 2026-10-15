# About Clipeus

Clipeus started as a "simple" domain name scanner and enumerator that grew into what feels like a wide-scoped security assessment of any domains you might own or want to scan (assuming you have permission).

I originally started creating this to get signal about the domains I have some responsibility for and I wanted to see the following details and more:

* subdomains that exist
* mail configurations for domains
* TLS implementation and configuration including certificate details, TLS version
* if redirects were present and if they were wholly TLS routes or not
* where a service might be hosted
* if dangling domains, CNAMEs and so on exist
* what other services might be available at the resolved host

This tool has been used to clean up my own hosted domains and obtain an inventory of other domains I was tasked to assess.

I have open-sourced the tool as I found out about Autumn-27's ARTEX which is a Grok AI-augmented tool similar to my scanner - the vital difference being that I aim for AI tooling only to support the scanning of domains and to assess the results for threats and risks.
