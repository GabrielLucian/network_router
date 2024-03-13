Scopul programului este de a simula o retea de Routere pentru o mai buna intelegere a modului de functionare a acestora.

Routerul verifica destinatia pachetului primit, dupa care verifica tipul de pachet (ARP sau IP).
Pentru pachetele IP se verifica checksum-ul, TTL-ul si se verifica daca pachetul trebuie sa fie trimis mai departe sau daca trebuie sa fie procesat.
Daca trebuie trimis mai departe, se verifica daca exista o ruta in tabela de rutare (cu cel mai mare mask), apoi se cauta in ARP table daca este un entry. Daca nu este se baga pachetul in coada de pachete si se trimite un ARP request. Daca este un entry in ARP table, se trimite pachetul mai departe.

Daca pachetul trebuie procesat, se verifica daca este un pachet ICMP echo request, daca da se trimite un pachet ICMP echo reply. 
Daca nu se poate ajunge la destinatie in Routing table, se trimite un pachet ICMP port unreachable.
Daca pachetul are TTL prea mic se trimite un pachet ICMP TTL expired.

Daca pachetul este ARP, se verifica daca este un ARP request, daca da se trimite un ARP reply. Daca nu, se verifica daca este un ARP reply, daca da se cauta in coada de pachete daca exista un pachet care asteapta un reply pentru adresa din pachetul primit. Daca da, se trimite pachetul mai departe.
