// should be const
static struct _oauth2_config conf[] = {
	{
		"https://accounts.google.com/o/oauth2/auth", /* auth_server */
		"https://accounts.google.com/o/oauth2/token", /* token_server */
		"", /* client id */
		"", /* client_secret */
		"", /* redirect uri */
		"https://mail.google.com%20https://docs.google.com/feeds", /* scope */
		NULL /* state */
	}
};
