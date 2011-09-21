#ifndef __POP3__ATTR__H
#define __POP3__ATTR__H

#define check_format(type, which, nargs) __attribute__((format(type, which, nargs)))
#define warn_unchecked_return __attribute__((warn_unused_result))

#endif
