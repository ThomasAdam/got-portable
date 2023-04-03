REGRESS_TARGETS =	00-empty \
			01-noise-only \
			02-only-verbatim \
			03-block \
			04-flow \
			05-loop \
			06-escape \
			07-printf \
			08-dangling

REGRESS_CLEANUP =	clean-comp
NO_OBJ =		Yes

CFLAGS +=		-I../../template

.PATH:../../template

clean-comp:
	rm -f t got 0*.[cdo] runbase.[do] runlist.[do] tmpl.*

.SUFFIXES: .tmpl .c .o

.tmpl.c:
	../../template/obj/template -o $@ $<

00-empty:
	../../template/obj/template 00-empty.tmpl >/dev/null

01-noise-only:
	../../template/obj/template 01-noise-only.tmpl >/dev/null

02-only-verbatim: 02-only-verbatim.o tmpl.o
	${CC} 02-only-verbatim.o tmpl.o -o t && ./t > got
	diff -u ${.CURDIR}/02.expected got

03-block: 03-block.o runbase.o tmpl.o
	${CC} 03-block.o runbase.o tmpl.o -o t && ./t > got
	diff -u ${.CURDIR}/03.expected got

04-flow: 04-flow.o runbase.o tmpl.o
	${CC} 04-flow.o runbase.o tmpl.o -o t && ./t > got
	diff -u ${.CURDIR}/04.expected got

05-loop: 05-loop.o runlist.o tmpl.o
	${CC} 05-loop.o runlist.o tmpl.o -o t && ./t > got
	diff -u ${.CURDIR}/05.expected got

06-escape: 06-escape.o runbase.o tmpl.o
	${CC} 06-escape.o runbase.o tmpl.o -o t && ./t > got
	diff -u ${.CURDIR}/06.expected got

07-printf: 07-printf.o runbase.o tmpl.o
	${CC} 07-printf.o runbase.o tmpl.o -o t && ./t > got
	diff -u ${.CURDIR}/07.expected got

08-dangling: 08-dangling.o runbase.o tmpl.o
	${CC} 08-dangling.o runbase.o tmpl.o -o t && ./t > got
	diff -u ${.CURDIR}/08.expected got

.include <bsd.regress.mk>
