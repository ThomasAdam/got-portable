SUBDIR = libexec got tog

.if make(regress)
SUBDIR += regress
.endif

.include <bsd.subdir.mk>
