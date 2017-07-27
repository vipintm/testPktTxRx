all: testPkt_tx testPkt_rx

testPkt_tx : testPkt_tx.c
	${CC} -Wall testPkt_tx.c -o testPkt_tx -lpcap -lmraa

testPkt_rx : testPkt_rx.c
	${CC} -Wall testPkt_rx.c -o testPkt_rx -lpcap -lmraa

clean:
	rm -f testPkt_tx *~
	rm -f testPkt_rx *~

send: 
	scp testPkt_rx testPkt_tx root@10.0.1.193:/media/realroot/
	scp testPkt_rx testPkt_tx root@10.0.1.192:/media/realroot/

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp testPkt_rx testPkt_tx $(DESTDIR)/usr/bin

