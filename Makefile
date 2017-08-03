all: testPkt_tx testPkt_rx

pushtest: clean testPkt_tx testPkt_rx send

testPkt_tx : src/testPkt_tx.c
	${CC} -Wall src/testPkt_tx.c -o build/testPkt_tx -lpcap -lmraa

testPkt_rx : src/testPkt_rx.c
	${CC} -Wall src/testPkt_rx.c -o build/testPkt_rx -lpcap -lmraa

clean:
	rm -f build/testPkt_tx *~
	rm -f build/testPkt_rx *~

send: 
	scp build/testPkt_rx build/testPkt_tx scripts/setup.sh test/run.sh root@10.0.1.193:/media/realroot/
	scp build/testPkt_rx build/testPkt_tx scripts/setup.sh test/run.sh root@10.0.1.192:/media/realroot/

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp build/testPkt_rx $(DESTDIR)/usr/bin
	cp build/testPkt_tx $(DESTDIR)/usr/bin
