#ifndef __POP3__AUTH__FACTORY__H
#define __POP3__AUTH__FACTORY__H

#include <common/pop3defs.h>
#include "pop3authmodule.h"
#include "pop3clearmech.h"
#include "pop3apopmech.h"
#include "pop3anonymousmech.h"
#include "pop3plainmech.h"
#include "pop3loginmech.h"
#include "pop3crammd5mech.h"
#include "pop3digestmd5mech.h"
#include "pop3ntlmmech.h"
#include "pop3gssapimech.h"

namespace pop3
{
	class Pop3AuthFactory
	{
		public:
			static Pop3AuthModule* GetAuthModule(const pop3auth::POP3_AUTH_TYPE_E auth_type);
	};
}

#endif
