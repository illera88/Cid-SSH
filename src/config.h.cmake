/* Define to 1 if you have the `pthread' library (-lpthread). */
#cmakedefine HAVE_PTHREAD 1

/* Set HOST_NAME_MAX and LOGIN_NAME_MAX */
#include <limits.h>

#ifndef HOST_NAME_MAX
# if defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# endif
#endif /* HOST_NAME_MAX */


#ifndef LOGIN_NAME_MAX
# if defined(_POSIX_LOGIN_NAME_MAX)
#  define LOGIN_NAME_MAX _POSIX_LOGIN_NAME_MAX
# else
#  define LOGIN_NAME_MAX 64
# endif
#endif /* LOGIN_NAME_MAX */
