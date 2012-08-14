<?php
/*
Plugin Name: Code for the People Email Authentication
Plugin URI:  http://codeforthepeople.com
Description: A plugin that uses email to authenticate WordPress users
Version: 0.0.1
Author: Mike Little (for Code for the People)
Author URI: http://zed1.com/
License: GPL2+
*/
/*
Copyright 2012 Code for the People

This file is part of The Code for the People Email Authentication Plugin.

The Code for the People Email Authentication Plugin is free software:
you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation,
either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

define( 'CFTP_EMAIL_AUTH_PLUGIN_NAME', 'cftp_email_auth' );
define( 'CFTP_EMAIL_AUTH_VERSION', '0.0.1' );
define( 'CFTP_EMAIL_AUTH_VERSION_OPTION', 'cftp_email_auth_plugin_version' );
define( 'CFTP_EMAIL_AUTH_OPTIONS', 'cftp_email_auth_options' );

define( 'CFTP_EMAIL_AUTH_TOKEN_META_KEY', '_cftp_auth_' );

if (!defined('NL'))	define('NL', "\n");

//this needs to be global to be accessible from a static class method :(
$cftp_email_auth_default_options = array(
	'email_domain' => '',
	'token_lifetime' => '5',
);

$cftp_consonants  = 'bcdfghjklmnprstvwz'; //consonants except hard to speak ones
$cftp_vowels	  = 'aeiou';              //vowels
$cftp_letters	  = $cftp_consonants.$cftp_vowels; //both

class cftp_email_auth {

	function __construct() {
		//zed1_debug();
		//add_action(	'init', array( 'cftp_email_auth', 'catch_login' ) );
		add_action( 'init', array( 'cftp_email_auth', 'init' ) );
	} // end constructor

	static function init() {
		//zed1_debug();
		self::catch_login();

		$needs_flush = false;
		$cftp_email_auth_version = get_option( CFTP_EMAIL_AUTH_VERSION_OPTION );
		if ( empty( $cftp_email_auth_version ) ) { // first time?
			add_option( CFTP_EMAIL_AUTH_VERSION_OPTION, CFTP_EMAIL_AUTH_VERSION );
        }
		// version check and maybe update
        if (version_compare($cftp_email_auth_version, CFTP_EMAIL_AUTH_VERSION, '<')) {
			self::upgrade_plugin($cftp_email_auth_version);
			$needs_flush = true;
            update_option( CFTP_EMAIL_AUTH_VERSION_OPTION, CFTP_EMAIL_AUTH_VERSION );
        }

		if ( $needs_flush ) {
			global $wp_rewrite;
			$wp_rewrite->flush_rules();
		}

		load_plugin_textdomain( 'cftp_email_auth', false, basename( dirname(__FILE__) ) . '/languages' );

		//zed1_debug("adding login_init action");
		add_action( 'login_init', array( 'cftp_email_auth', 'login_init' ) );
		//zed1_debug("added login_init action");
		//add_action(	'login_form', array( 'cftp_email_auth', 'login_form' ) );
		add_action(	'login_form_token', array( 'cftp_email_auth', 'login_form_token' ) );

		remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
		add_filter( 'authenticate', array( 'cftp_email_auth', 'authenticate' ), 20, 3 );

		//apply_filters('auth_cookie_expiration', 1209600, $user_id, $remember)

		add_filter( 'wpmu_welcome_user_notification', array( 'cftp_email_auth', 'wpmu_welcome_user_notification'), 10, 3 );
		add_filter( 'wpmu_signup_user_notification', array( 'cftp_email_auth', 'wpmu_signup_user_notification'), 10, 4 );


		/* admin only hooks below here */
		if ( !is_admin() )
			return;

		add_action( 'admin_init', array( 'cftp_email_auth', 'admin_init' ) );
		add_action( 'admin_menu', array( 'cftp_email_auth', 'admin_menu' ) );

		//add_action( 'admin_print_scripts', array( 'cftp_email_auth', 'admin_print_scripts' ) );
		add_action('admin_print_scripts-user-new.php',	array( 'cftp_email_auth', 'enqueue_admin_scripts' ) );
		
	} // end init

	static function admin_init() {
		//zed1_debug();
		register_setting( CFTP_EMAIL_AUTH_OPTIONS, CFTP_EMAIL_AUTH_OPTIONS, array( 'cftp_email_auth', 'validate_options' ) );

		add_settings_section( CFTP_EMAIL_AUTH_OPTIONS . '-main',										// html id
							  __( 'Security settings', 'cftp_email_auth' ),								// title
							  array( 'cftp_email_auth', 'main_section' ),								// callback
							  CFTP_EMAIL_AUTH_PLUGIN_NAME . '-main' );									// page

		add_settings_field( CFTP_EMAIL_AUTH_OPTIONS . '_email_domain',									// html id
							'<label for="email_domain">' . __( 'Restrict emails to this domain', 'cftp_email_auth' ) . '</label>',	// title
							array( 'cftp_email_auth', 'settings_input_field' ),							// callback
							CFTP_EMAIL_AUTH_PLUGIN_NAME . '-main',										// page
							CFTP_EMAIL_AUTH_OPTIONS . '-main',											// section
							array( 'fieldname' => 'email_domain',
								   'hint' => __( 'Only enter the part after the @ sign.', 'cftp_email_auth' ) ) ); // args


		add_settings_field( CFTP_EMAIL_AUTH_OPTIONS . '_token_lifetime',								// html id
							'<label for="token_lifetime">' . __( 'Token timeout (minutes)', 'cftp_email_auth' ) . '</label>',	// title
							array( 'cftp_email_auth', 'settings_input_field' ),							// callback
							CFTP_EMAIL_AUTH_PLUGIN_NAME . '-main',										// page
							CFTP_EMAIL_AUTH_OPTIONS . '-main',											// section
							array( 'fieldname' => 'token_lifetime',
								   'hint' => __( 'This should reflect a reasonable amount of time to recieve an email after attempting to login.', 'cftp_email_auth' ) ) ); // args

	} // end admin_init

	static function main_section() {
		//zed1_debug();
		$options = self::get_options();
		echo __( '<p class="section-description" id="main_section">Please fill in these security settings. '
				   . "If you wish to restrict user registration to only allow emails from a specific domain, fill in the 'Restrict emails to this domain' field</p>"
				   . '<p>Set the token timeout to according to the expected speed of your email system.</p>', 'cftp_email_auth' )
				. NL;
	}


	static function settings_input_field( $args ) {
		//zed1_debug( $args );
		$options = self::get_options();
		if (isset($args) && !empty($args)) {
			echo '<input type="text" name="' . CFTP_EMAIL_AUTH_OPTIONS . '[' . $args['fieldname'] . ']" id="' . $args['fieldname'] . '" size="30" value="' . esc_attr(self::array_as_list($options[$args['fieldname']])) . '" />' . NL;
			if (isset($args['hint'])) {
				echo '<span class="hint-text">' . $args['hint'] . '</span>' . NL;
			}
		} else {
			echo 'settings_input_field() bad call!' . NL;
		}
	} // end settings_input_field

	static function array_as_list($value) {
		if (is_array($value))
			return implode(',', $value);
		else
			return $value;
	} // end array_as_list


	static function validate_options( $input ) {
		//zed1_debug($input);

		$options = self::get_options();

		$valid = array();
		$valid['email_domain'] = trim( $input['email_domain'] );
		$valid['token_lifetime'] = intval( trim( $input['token_lifetime'] ) );
		//zed1_debug( "valid=" . var_export( $valid, true ) );
		return $valid;
	}


	static function admin_menu() {
		//zed1_debug();

		$options = self::get_options();
		// add ourselves under the settings menu
		$options_page = add_options_page( __( 'Email Authentication', 'cftp_email_auth' ),
						  __( 'Email Authentication', 'cftp_email_auth' ),
						  'administrator',
						  CFTP_EMAIL_AUTH_PLUGIN_NAME.'_settings',
						  array( 'cftp_email_auth', 'display_options_page' )
						);
		//zed1_debug( $options_page );

		wp_register_style( 'cftp-email-auth', plugins_url( 'css/cftp-email-auth.css', __FILE__ ), array(), CFTP_EMAIL_AUTH_VERSION );
		wp_register_script( 'cftp-email-auth', plugins_url( 'js/cftp-email-auth.js', __FILE__ ), array(), CFTP_EMAIL_AUTH_VERSION );

		add_action('admin_print_styles-' . $options_page,	array( 'cftp_email_auth', 'enqueue_admin_style' ) );
		add_action('admin_print_scripts-' . $options_page,	array( 'cftp_email_auth', 'enqueue_admin_scripts' ) );
	} // end admin_menu

	static function display_options_page() {
		//zed1_debug();
		global $wpdb;
		//zed1_debug("post=", $_POST);

		echo '<div class="wrap">' . NL;
		echo get_screen_icon( CFTP_EMAIL_AUTH_PLUGIN_NAME );
		echo '<h2>' . __( 'Email Authentication', 'cftp_email_auth' ) . '</h2>' . NL;

		echo '<form method="post" action="options.php">';
		settings_fields( CFTP_EMAIL_AUTH_OPTIONS );
		echo '<div id="tab-container">';
		do_settings_sections( CFTP_EMAIL_AUTH_PLUGIN_NAME . '-main' );
		echo '</div>';

		echo '<p class="submit">';
		submit_button();
		echo '</p>';

		echo '</form>';
		echo '</div><!-- .wrap -->' . NL;

	} // end display_options_page

    static function enqueue_admin_style() {
		//zed1_debug();
		wp_enqueue_style( 'cftp-email-auth' );
    } // end enqueue_admin_style

    static function enqueue_admin_scripts() {
		//zed1_debug();
		wp_enqueue_script( 'cftp-email-auth' );
    } // end enqueue_admin_scripts


	// options function ///////////////////////////////////

	static function get_options() {
		global $cftp_email_auth_default_options;
		$options   =  get_option( CFTP_EMAIL_AUTH_OPTIONS );
		//error_log("get_options: got options = " . var_export( $options, true ));
		if ( !is_array( $options ) )
			$options = array();

		$options = array_merge( $cftp_email_auth_default_options, $options );
		//error_log("get_options: after merge options = " . var_export( $options, true ));

		return $options;
	} // end get_options

	static function update_options($new_options) {
		//zed1_debug("new_options = " . var_export( $new_options, true ));

		$old_options = self::get_options();
		//zed1_debug("old-options = " . var_export( $old_options, true ));
		$options = array_merge($old_options, $new_options);
		//zed1_debug("merged options = " . var_export( $options, true ));

		//zed1_debug("blog_id = $blog_id");
		update_option( CFTP_EMAIL_AUTH_OPTIONS, $options );

		return $options;
	} // end update_options

	static function get_option($key) {
		global $cftp_email_auth_default_options;
		$options   =  self::get_options();
		//error_log("get_option: got options = " . var_export( $options, true ));
		if (isset($options[$key]))
			return $options[$key];
		return '';
	} // end get_option

	// end options function ///////////////////////////////////


	// authentication functions ///////////////////////////////////

	/* let's take over wp-login.php */
	static function login_init() {
		//zed1_debug();
		$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : 'login';
		$errors = new WP_Error();

		if ( isset($_GET['key']) )
			$action = 'resetpass';

		// validate action so as to default to the login screen
		if ( !in_array( $action, array( 'postpass', 'logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register', 'login' ), true ) && false === has_filter( 'login_form_' . $action ) )
			$action = 'login';

		do_action( 'login_form_' . $action );

		nocache_headers();

		header('Content-Type: '.get_bloginfo('html_type').'; charset='.get_bloginfo('charset'));

		if ( defined('RELOCATE') ) { // Move flag is set
			if ( isset( $_SERVER['PATH_INFO'] ) && ($_SERVER['PATH_INFO'] != $_SERVER['PHP_SELF']) )
				$_SERVER['PHP_SELF'] = str_replace( $_SERVER['PATH_INFO'], '', $_SERVER['PHP_SELF'] );

			$schema = is_ssl() ? 'https://' : 'http://';
			if ( dirname($schema . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF']) != get_option('siteurl') )
				update_option('siteurl', dirname($schema . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF']) );
		}

		//Set a cookie now to see if they are supported by the browser.
		setcookie(TEST_COOKIE, 'WP Cookie check', 0, COOKIEPATH, COOKIE_DOMAIN);
		if ( SITECOOKIEPATH != COOKIEPATH )
			setcookie(TEST_COOKIE, 'WP Cookie check', 0, SITECOOKIEPATH, COOKIE_DOMAIN);

		// allow plugins to override the default actions, and to add extra actions if they want
		// do_action( 'login_init' ); // we are already doing this action
		//do_action( 'login_form_' . $action ); moved to earlier

		$http_post = ('POST' == $_SERVER['REQUEST_METHOD']);
		switch ($action) {

			case 'postpass' :
				if ( empty( $wp_hasher ) ) {
					require_once( ABSPATH . 'wp-includes/class-phpass.php' );
					// By default, use the portable hash from phpass
					$wp_hasher = new PasswordHash(8, true);
				}

				// 10 days
				setcookie( 'wp-postpass_' . COOKIEHASH, $wp_hasher->HashPassword( stripslashes( $_POST['post_password'] ) ), time() + 864000, COOKIEPATH );

				wp_safe_redirect( wp_get_referer() );
				exit();

				break;

			case 'logout' :
				check_admin_referer('log-out');
				wp_logout();

				$redirect_to = !empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : 'wp-login.php?loggedout=true';
				wp_safe_redirect( $redirect_to );
				exit();

				break;

			case 'lostpassword' :
			case 'retrievepassword' :

				if ( $http_post ) {
					$errors = retrieve_password();
					if ( !is_wp_error($errors) ) {
						$redirect_to = !empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : 'wp-login.php?checkemail=confirm';
						wp_safe_redirect( $redirect_to );
						exit();
					}
				}

				if ( isset($_GET['error']) && 'invalidkey' == $_GET['error'] ) $errors->add('invalidkey', __('Sorry, that key does not appear to be valid.'));
				$redirect_to = apply_filters( 'lostpassword_redirect', !empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : '' );

				do_action('lost_password');
				login_header(__('Lost Password'), '<p class="message">' . __('Please enter your username or email address. You will receive a link to create a new password via email.') . '</p>', $errors);

				$user_login = isset($_POST['user_login']) ? stripslashes($_POST['user_login']) : '';

?>

<form name="lostpasswordform" id="lostpasswordform" action="<?php echo esc_url( site_url( 'wp-login.php?action=lostpassword', 'login_post' ) ); ?>" method="post">
  <p>
	<label for="user_login" ><?php _e('Username or E-mail:') ?><br />
	  <input type="text" name="user_login" id="user_login" class="input" value="<?php echo esc_attr($user_login); ?>" size="20" tabindex="10" /></label>
  </p>
<?php do_action('lostpassword_form'); ?>
  <input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
  <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button-primary" value="<?php esc_attr_e('Get New Password'); ?>" tabindex="100" /></p>
</form>

<p id="nav">
<a href="<?php echo esc_url( wp_login_url() ); ?>"><?php _e('Log in') ?></a>
<?php if ( get_option( 'users_can_register' ) ) : ?>
  | <a href="<?php echo esc_url( site_url( 'wp-login.php?action=register', 'login' ) ); ?>"><?php _e( 'Register' ); ?></a>
<?php endif; ?>
</p>

<?php
			    login_footer('user_login');
				break;


			case 'token':

				$token_login = isset($_REQUEST['token_login']) ? $_REQUEST['token_login'] : '';
				//zed1_debug("token_login=$token_login");
/*
				$token_login = trim( $token_login );
				//zed1_debug("token_login=$token_login");

				$token_login = str_replace( ' ', '', $token_login );
				//zed1_debug("token_login=$token_login");

				$token_login = strtolower( $token_login );
				//zed1_debug("token_login=$token_login");
*/

				//$errors = new WP_Error();
				if ( !empty( $token_login ) ) {
					$errors->add('token_login', __('<strong>The token was not recognized or has timed out</strong>: Did you type it correctly?'));
				}

				login_header(__('Login Token'), '<p class="message">' . __('Please enter the token you recieved at your registered email address.') . '</p>', $errors);

				//$user_login = isset($_POST['user_login']) ? stripslashes($_POST['user_login']) : '';

?>

<form name="tokenloginform" id="tokenloginform" action="<?php echo esc_url( site_url( 'wp-login.php?action=token', 'login_post' ) ); ?>" method="post">
  <p>
	<label for="token_login" ><?php _e('Token:') ?><br />
	  <input type="text" name="token_login" id="token_login" class="input" value="<?php echo esc_attr($token_login); ?>" size="20" tabindex="10" /></label>
  </p>
<?php do_action('tokenlogin_form'); ?>
  <input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
  <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button-primary" value="<?php esc_attr_e('Login'); ?>" tabindex="100" /></p>
</form>

<p id="nav">
<a href="<?php echo esc_url( wp_login_url() ); ?>"><?php _e('Log in') ?></a>
<?php if ( get_option( 'users_can_register' ) ) : ?>
  | <a href="<?php echo esc_url( site_url( 'wp-login.php?action=register', 'login' ) ); ?>"><?php _e( 'Register' ); ?></a>
<?php endif; ?>
</p>

<?php
			    login_footer('user_login');
				break;


			case 'resetpass' :
			case 'rp' :
				$user = check_password_reset_key($_GET['key'], $_GET['login']);

				if ( is_wp_error($user) ) {
					wp_redirect( site_url('wp-login.php?action=lostpassword&error=invalidkey') );
					exit;
				}

				$errors = '';

				if ( isset($_POST['pass1']) && $_POST['pass1'] != $_POST['pass2'] ) {
					$errors = new WP_Error('password_reset_mismatch', __('The passwords do not match.'));
				} elseif ( isset($_POST['pass1']) && !empty($_POST['pass1']) ) {
					reset_password($user, $_POST['pass1']);
					login_header( __( 'Password Reset' ), '<p class="message reset-pass">' . __( 'Your password has been reset.' ) . ' <a href="' . esc_url( wp_login_url() ) . '">' . __( 'Log in' ) . '</a></p>' );
					login_footer();
					exit;
				}

				wp_enqueue_script('utils');
				wp_enqueue_script('user-profile');

				login_header(__('Reset Password'), '<p class="message reset-pass">' . __('Enter your new password below.') . '</p>', $errors );

?>
<form name="resetpassform" id="resetpassform" action="<?php echo esc_url( site_url( 'wp-login.php?action=resetpass&key=' . urlencode( $_GET['key'] ) . '&login=' . urlencode( $_GET['login'] ), 'login_post' ) ); ?>" method="post">
  <input type="hidden" id="user_login" value="<?php echo esc_attr( $_GET['login'] ); ?>" autocomplete="off" />

  <p>
	<label for="pass1"><?php _e('New password') ?><br />
	  <input type="password" name="pass1" id="pass1" class="input" size="20" value="" autocomplete="off" /></label>
  </p>
  <p>
	<label for="pass2"><?php _e('Confirm new password') ?><br />
	  <input type="password" name="pass2" id="pass2" class="input" size="20" value="" autocomplete="off" /></label>
  </p>

  <div id="pass-strength-result" class="hide-if-no-js"><?php _e('Strength indicator'); ?></div>
  <p class="description indicator-hint"><?php _e('Hint: The password should be at least seven characters long. To make it stronger, use upper and lower case letters, numbers and symbols like ! " ? $ % ^ &amp; ).'); ?></p>

  <br class="clear" />
  <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button-primary" value="<?php esc_attr_e('Reset Password'); ?>" tabindex="100" /></p>
</form>

<p id="nav">
<a href="<?php echo esc_url( wp_login_url() ); ?>"><?php _e( 'Log in' ); ?></a>
<?php if ( get_option( 'users_can_register' ) ) : ?>
  | <a href="<?php echo esc_url( site_url( 'wp-login.php?action=register', 'login' ) ); ?>"><?php _e( 'Register' ); ?></a>
<?php endif; ?>
</p>

<?php
			    login_footer('user_pass');
				break;

			case 'register' :
				if ( is_multisite() ) {
				// Multisite uses wp-signup.php
					wp_redirect( apply_filters( 'wp_signup_location', site_url('wp-signup.php') ) );
					exit;
				}

				if ( !get_option('users_can_register') ) {
					wp_redirect( site_url('wp-login.php?registration=disabled') );
					exit();
				}

				$user_login = '';
				$user_email = '';
				if ( $http_post ) {
					$user_login = $_POST['user_login'];
					$user_email = $_POST['user_email'];
					$errors = register_new_user($user_login, $user_email);
					if ( !is_wp_error($errors) ) {
						$redirect_to = !empty( $_POST['redirect_to'] ) ? $_POST['redirect_to'] : 'wp-login.php?checkemail=registered';
						wp_safe_redirect( $redirect_to );
						exit();
					}
				}

				$redirect_to = apply_filters( 'registration_redirect', !empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : '' );
				login_header(__('Registration Form'), '<p class="message register">' . __('Register For This Site') . '</p>', $errors);
?>

<form name="registerform" id="registerform" action="<?php echo esc_url( site_url('wp-login.php?action=register', 'login_post') ); ?>" method="post">
  <p>
	<label for="user_login"><?php _e('Username') ?><br />
	  <input type="text" name="user_login" id="user_login" class="input" value="<?php echo esc_attr(stripslashes($user_login)); ?>" size="20" tabindex="10" /></label>
  </p>
  <p>
	<label for="user_email"><?php _e('E-mail') ?><br />
	  <input type="email" name="user_email" id="user_email" class="input" value="<?php echo esc_attr(stripslashes($user_email)); ?>" size="25" tabindex="20" /></label>
  </p>
<?php do_action('register_form'); ?>
  <p id="reg_passmail"><?php _e('A password will be e-mailed to you.') ?></p>
  <br class="clear" />
  <input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
  <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button-primary" value="<?php esc_attr_e('Register'); ?>" tabindex="100" /></p>
</form>

<p id="nav">
<a href="<?php echo esc_url( wp_login_url() ); ?>"><?php _e( 'Log in' ); ?></a> |
<a href="<?php echo esc_url( wp_lostpassword_url() ); ?>" title="<?php esc_attr_e( 'Password Lost and Found' ) ?>"><?php _e( 'Lost your password?' ); ?></a>
</p>

<?php
				login_footer('user_login');
				break;

				//case 'emaillogin' :


			case 'login' :
			default:
				$secure_cookie = '';
				$interim_login = isset($_REQUEST['interim-login']);

				$customize_login = isset( $_REQUEST['customize-login'] );
				if ( $customize_login )
					wp_enqueue_script( 'customize-base' );

				// If the user wants ssl but the session is not ssl, force a secure cookie.
				if ( !empty($_POST['log']) && !force_ssl_admin() ) {
					$user_name = sanitize_user($_POST['log']);
					if ( $user = get_user_by('login', $user_name) ) {
						if ( get_user_option('use_ssl', $user->ID) ) {
							$secure_cookie = true;
							force_ssl_admin(true);
						}
					}
				}

				if ( isset( $_REQUEST['redirect_to'] ) ) {
					$redirect_to = $_REQUEST['redirect_to'];
					// Redirect to https if user wants ssl
					if ( $secure_cookie && false !== strpos($redirect_to, 'wp-admin') )
						$redirect_to = preg_replace('|^http://|', 'https://', $redirect_to);
				} else {
					$redirect_to = admin_url();
				}

				$reauth = empty($_REQUEST['reauth']) ? false : true;

				// If the user was redirected to a secure login form from a non-secure admin page, and secure login is required but secure admin is not, then don't use a secure
				// cookie and redirect back to the referring non-secure admin page.  This allows logins to always be POSTed over SSL while allowing the user to choose visiting
				// the admin via http or https.
				if ( !$secure_cookie && is_ssl() && force_ssl_login() && !force_ssl_admin() && ( 0 !== strpos($redirect_to, 'https') ) && ( 0 === strpos($redirect_to, 'http') ) )
					$secure_cookie = false;

				$user = wp_signon('', $secure_cookie);

				$redirect_to = apply_filters('login_redirect', $redirect_to, isset( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : '', $user);

				if ( !is_wp_error($user) && !$reauth ) {
					if ( $interim_login ) {
						$message = '<p class="message">' . __('You have logged in successfully.') . '</p>';
						login_header( '', $message ); ?>

			<?php if ( ! $customize_login ) : ?>
				<script type="text/javascript">setTimeout( function(){window.close()}, 8000);</script>
				<p class="alignright">
				<input type="button" class="button-primary" value="<?php esc_attr_e('Close'); ?>" onclick="window.close()" /></p>
			<?php endif; ?>
				</div>
			<?php do_action( 'login_footer' ); ?>
			<?php if ( $customize_login ) : ?>
				<script type="text/javascript">setTimeout( function(){ new wp.customize.Messenger({ url: '<?php echo wp_customize_url(); ?>', channel: 'login' }).send('login') }, 1000 );</script>
			<?php endif; ?>
			</body></html>
<?php		exit;
					}

					if ( ( empty( $redirect_to ) || $redirect_to == 'wp-admin/' || $redirect_to == admin_url() ) ) {
						// If the user doesn't belong to a blog, send them to user admin. If the user can't edit posts, send them to their profile.
						if ( is_multisite() && !get_active_blog_for_user($user->ID) && !is_super_admin( $user->ID ) )
							$redirect_to = user_admin_url();
						elseif ( is_multisite() && !$user->has_cap('read') )
								$redirect_to = get_dashboard_url( $user->ID );
					elseif ( !$user->has_cap('edit_posts') )
							$redirect_to = admin_url('profile.php');
					}
					wp_safe_redirect($redirect_to);
					exit();
				}

				$errors = $user;
				// Clear errors if loggedout is set.
				if ( !empty($_GET['loggedout']) || $reauth )
					$errors = new WP_Error();

					// If cookies are disabled we can't log in even with a valid user+pass
				if ( isset($_POST['testcookie']) && empty($_COOKIE[TEST_COOKIE]) )
					$errors->add('test_cookie', __("<strong>ERROR</strong>: Cookies are blocked or not supported by your browser. You must <a href='http://www.google.com/cookies.html'>enable cookies</a> to use WordPress."));

					// Some parts of this script use the main login form to display a message
				if ( isset($_GET['loggedout']) && true == $_GET['loggedout'] )
					$errors->add('loggedout', __('You are now logged out.'), 'message');
				elseif ( isset($_GET['registration']) && 'disabled' == $_GET['registration'] )
					$errors->add('registerdisabled', __('User registration is currently not allowed.'));
				elseif ( isset($_GET['checkemail']) && 'confirm' == $_GET['checkemail'] )
					$errors->add('confirm', __('Check your e-mail for the confirmation link.'), 'message');
				elseif ( isset($_GET['checkemail']) && 'newpass' == $_GET['checkemail'] )
					$errors->add('newpass', __('Check your e-mail for your new password.'), 'message');
				elseif	( isset($_GET['checkemail']) && 'registered' == $_GET['checkemail'] )
					$errors->add('registered', __('Registration complete. Please check your e-mail.'), 'message');
				elseif	( $interim_login )
					$errors->add('expired', __('Your session has expired. Please log-in again.'), 'message');
				elseif ( strpos( $redirect_to, 'about.php?updated' ) )
					$errors->add('updated', __( '<strong>You have successfully updated WordPress!</strong> Please log back in to experience the awesomeness.' ), 'message' );

				// Clear any stale cookies.
				if ( $reauth )
					wp_clear_auth_cookie();

				login_header(__('Log In'), '', $errors);

				if ( isset($_POST['log']) )
					$user_login = ( 'incorrect_password' == $errors->get_error_code() || 'empty_password' == $errors->get_error_code() ) ? esc_attr(stripslashes($_POST['log'])) : '';
				$rememberme = true; //! empty( $_POST['rememberme'] );
?>

<form name="loginform" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php', 'login_post' ) ); ?>" method="post">
  <p>
	<input name="rememberme" type="hidden" id="rememberme" value="forever" />
	<label for="user_login"><?php _e('Email address') ?><br />
	  <input type="text" name="log" id="user_login" class="input" value="<?php echo esc_attr($user_login); ?>" size="20" tabindex="10" /></label>
  </p>
<?php if (0) { /* don't need password field */ ?>
  <p>
	<label for="user_pass"><?php _e('Password') ?><br />
	  <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" tabindex="20" /></label>
  </p>
<?php } ?>
<?php do_action('login_form'); ?>
  <p class="submit">
	<input type="submit" name="wp-submit" id="wp-submit" class="button-primary" value="<?php esc_attr_e('Log In'); ?>" tabindex="100" />
<?php	if ( $interim_login ) { ?>
	<input type="hidden" name="interim-login" value="1" />
<?php	} else { ?>
	<input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>" />
<?php 	} ?>
<?php   if ( $customize_login ) : ?>
		<input type="hidden" name="customize-login" value="1" />
<?php   endif; ?>
	<input type="hidden" name="testcookie" value="1" />
  </p>
</form>

<?php if ( !$interim_login ) { ?>
<p id="nav">
<?php if ( isset($_GET['checkemail']) && in_array( $_GET['checkemail'], array('confirm', 'newpass') ) ) : ?>
<?php elseif ( get_option('users_can_register') ) : ?>
<a href="<?php echo esc_url( site_url( 'wp-login.php?action=register', 'login' ) ); ?>"><?php _e( 'Register' ); ?></a> |
<a href="<?php echo esc_url( wp_lostpassword_url() ); ?>" title="<?php esc_attr_e( 'Password Lost and Found' ); ?>"><?php _e( 'Lost your password?' ); ?></a>
<?php else : ?>
<a href="<?php echo esc_url( wp_lostpassword_url() ); ?>" title="<?php esc_attr_e( 'Password Lost and Found' ); ?>"><?php _e( 'Lost your password?' ); ?></a>
<?php endif; ?>
</p>
<?php } ?>

<script type="text/javascript">
  function wp_attempt_focus(){
setTimeout( function(){ try{
<?php if ( $user_login || $interim_login ) { ?>
d = document.getElementById('user_pass');
d.value = '';
<?php } else { ?>
d = document.getElementById('user_login');
<?php if ( 'invalid_username' == $errors->get_error_code() ) { ?>
if( d.value != '' )
d.value = '';
<?php
}
}?>
d.focus();
d.select();
} catch(e){}
}, 200);
}

<?php if ( !$error ) { ?>
wp_attempt_focus();
<?php } ?>
if(typeof wpOnload=='function')wpOnload();
</script>

<?php
login_footer();
break;
} /* end action switch */

		exit();
	} // end login_init

	static function login_form() {
		//zed1_debug();
		$user_email = '';

?>
  <p>Or login with your email:<br />
	<label for="user_email"><?php _e('E-mail') ?><br />
	  <input type="email" name="user_email" id="user_email" class="input" value="<?php echo esc_attr(stripslashes($user_email)); ?>" size="25" tabindex="20" /></label>
  </p>

<?php
	} // end login_form


	static function authenticate( $user, $username, $password ) {
		if ( !empty( $username ) )
			$user = get_user_by( 'email', $username );

		//zed1_debug($user);

		if ( isset( $user, $user->user_login ) ) {
			$username = $user->user_login;
			$useremail = $user->user_email;
		} else {
			$error = new WP_Error();
			if ( !empty( $username ) ) {
				$error->add('user', __('<strong>Your email address was not recognized</strong>: Did you type it correctly?'));
			}
			return $error;
		}

		// create a token
		$token = self::generate_token();
		//zed1_debug("generated token ", $token);
		//zed1_debug("_SERVER ", $_SERVER);
		// store the token against the user, with a timestamp
		$data = array( 'token' => $token, 'ip' => $_SERVER['REMOTE_ADDR'], 'time' => time(), 'user_id' => $user->ID );
		//zed1_debug("data ", $data);

		set_site_transient( CFTP_EMAIL_AUTH_TOKEN_META_KEY . $token[4], $data, self::get_option( 'token_lifetime' ) * 60 );
		// update_user_meta( $user->ID, CFTP_EMAIL_AUTH_TOKEN_META_KEY . $token[4], $data);

		$message = "\n
To login to [SITENAME], please visit the following address: [LOGINLINK] \n
If the link does not work please visit [LOGINPAGE] and type in the following code: \n
[TOKEN]

Thanks,
the [SITENAME] team
";

		$message = str_replace('[SITENAME]', get_bloginfo( 'sitename' ) ,  $message);
		$message = str_replace('[LOGINLINK]', site_url( '/login/' . urlencode( $token[4]  ) ),  $message);

		$message = str_replace('[LOGINPAGE]', site_url( '/login/' ),  $message);
		unset( $token[4] );
		$message = str_replace('[TOKEN]', implode( ' ', $token ),  $message);
		//zed1_debug($message);

		$subject = "[SITENAME] - login";
		$subject = str_replace('[SITENAME]', get_bloginfo( 'sitename' ) ,  $subject);
		//zed1_debug($subject);

		$res = wp_mail( $useremail, $subject, $message);

		$error = new WP_Error();

		$error->add('information', __('<strong>Login link sent</strong>: Please check your email for your login link.'));

		return $error;
		//return wp_authenticate_username_password( null, $username, $password );
	} // end authenticate


	static function generate_token() {
		$token = array();
		for( $i = 0; $i < 4; $i++)
			$token[] = self::get_token_part();
		$token[] = implode( '', $token );
		return $token;
	} // end generate_token

	static function get_token_part(){
		global $cftp_consonants, $cftp_vowels,$cftp_letters;

		$pw = '';

		// a consonant, a vowel, and two random letters please, Carol.
		$pw .= $cftp_consonants[mt_rand(0, 17)]; // strlen($cftp_consonants) - 1 -- Note number hard-coded for speed
		$pw .= $cftp_vowels[mt_rand(0, 4)];  // strlen($cftp_vowels) - 1
		$pw .= $cftp_letters[mt_rand(0, 22)]; // strlen($cftp_letters) - 1
		$pw .= $cftp_letters[mt_rand(0, 22)]; // strlen($cftp_letters) - 1
		//$pw .= rand(10,99);

		return $pw;
	} // end get_token_part


	static function login_form_token() {
		//zed1_debug();
		$token_login = isset($_REQUEST['token_login']) ? $_REQUEST['token_login'] : '';
		//zed1_debug("token_login=$token_login");

		$token_login = trim( $token_login );
		//zed1_debug("token_login=$token_login");

		$token_login = str_replace( ' ', '', $token_login );
		//zed1_debug("token_login=$token_login");

		$token_login = strtolower( $token_login );
		//zed1_debug("token_login=$token_login");

		self::authorise_with_token( $token_login );

	} // end login_form_token


	static function catch_login() {
		//zed1_debug($_SERVER['REQUEST_URI']);
		if ( false !== strpos( $_SERVER['REQUEST_URI'], '/login') ) {
			$url = $_SERVER['REQUEST_URI'];
			$p = strpos( $_SERVER['REQUEST_URI'], '/login/') + strlen( '/login/' );
			$token_login = strtolower( substr( $url, $p ) );
			//zed1_debug("token_login=$token_login");

			self::authorise_with_token( $token_login );

			// if we get here, it;s either an invalid token, or not found coz it timed out.
			//redirect to wp-login.php with param token
			wp_redirect( site_url( 'wp-login.php?action=token' ) );
			exit;
		}
	}

	static function authorise_with_token( $token_login ) {
		if ( strlen( $token_login ) == 16 ) {

			$data = get_site_transient( CFTP_EMAIL_AUTH_TOKEN_META_KEY . $token_login );
			//zed1_debug("data=", $data);

			$user_id = $data['user_id'];
			//zed1_debug("user_id=$user_id");

			// check token matches (duh! we wouldn't have found it)
			if ( $token_login === $data['token'][4] ) {
				// check for timeout
				//zed1_debug("token_lifetime=", self::get_option( 'token_lifetime' ));
				//zed1_debug("time=",time());
				//zed1_debug("data[time]=",$data['time']);
				if ( $data['time'] + ( self::get_option( 'token_lifetime' ) * 60 ) > time() ) {
					// check ip matches
					//zed1_debug("ip=",$_SERVER['REMOTE_ADDR']);
					if ( $data['ip'] ===  $_SERVER['REMOTE_ADDR'] ) {
						// good to go. log the user in
						//zed1_debug("good to go");

						$user = get_user_by( 'id', $user_id );
						//zed1_debug($user);
						$user_login = $user->user_login;
						wp_set_current_user($user_id, $user_login);
						wp_set_auth_cookie($user_id, true);

						// we can delete this transient now
						delete_site_transient( CFTP_EMAIL_AUTH_TOKEN_META_KEY . $token_login );

						do_action('wp_login', $user_login);


						wp_redirect( site_url() );

						exit;
					} else {
					// error ip doesn't match
						zed1_debug("ip doesn't match");
					}
				} else {
				// timed out
					zed1_debug("timed out");
				}
			} else {
			//invalid token
				zed1_debug("invalid token");
			}
		} // end if length ok
	} // end authorise_with_token


	static function wpmu_welcome_user_notification( $user_id, $password, $meta ) {
		//zed1_debug( $user_id, $password, $meta );
		return false;
	} // end wpmu_welcome_user_notification

	static function wpmu_signup_user_notification( $user, $user_email, $key, $meta ) {
		//zed1_debug( $user, $user_email, $key, $meta );
		return false;
	} // end wpmu_signup_user_notification

	// end authentication function ///////////////////////////////////


	// upgrade functions /////////////////////////////////

    static function upgrade_plugin( $version ) {
        global $wpdb;
        // upgrade from 0.0.1 -> 0.0.2
        if (version_compare($version, '0.0.2', '<')) {
            // do something
            $version = '0.0.2';
        } // end if upgrade to 0.0.2

		// next test...
        return $version;
    } // end upgrade_plugin


	// end upgrade functions /////////////////////////////////

} // end class cftp_email_auth

/* utility function used by everything */
if ( !function_exists( 'zed1_debug' ) ) {
function zed1_debug( $message= '' ) {
	$trace = debug_backtrace();
	array_shift( $trace ); // discard ourselves
	$caller = array_shift( $trace );
	$func = $caller['function'];
	if ( isset( $caller['class'] ) )
		$func = $caller['class'] . '::' . $func;
	$out = $func . '() ';
	if ( is_scalar( $message ) )
		$out .= $message;
	else
		$out .= ' ' . var_export( $message, true );

	$args = array_slice( func_get_args(), 1 );
	if ( !empty( $args ) )
		foreach ( $args as $arg )
			$out .= ' ' . var_export( $arg, true );

	error_log( $out );
} // end zed1_debug()
}

new cftp_email_auth();
