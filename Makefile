SUBDIR = libexec got tog

.if make(regress) || make(obj)
SUBDIR += regress
.endif

.include <bsd.subdir.mk>
