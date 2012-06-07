<?php
/*
Plugin Name: Code for the People Email Authentication
Plugin URI: http://puffbox.com/
Description: A plugin that uses email to authenticate WordPress users
Version: 0.0.1
Author: Mike Little
Author URI: http://zed1.com/
License: GPL2+
*/
/*
    Copyright 2011 Code for the People

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
define( 'CFTP_EMAIL_AUTH_PLUGIN_VERSION', '0.0.1' );
define( 'CFTP_EMAIL_AUTH_VERSION_OPTION', 'cftp_email_auth_plugin_version' );

define( 'CFTP_EMAIL_AUTH_SOME_THING_META_TAG', '_cftp_email_auth_some_thing' );

if (!defined('NL'))	define('NL', "\n");

class cftp_email_auth {

	function __construct() {
		//zed1_debug();
		add_action( 'init', array( 'cftp_email_auth', 'init' ) );
	} // end constructor


	static function init() {
		//zed1_debug();

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

		/* admin only hooks below here */
		if ( !is_admin() )
			return;

		add_action( 'admin_menu', array( 'cftp_email_auth', 'meta_boxes' ) );
		add_action( 'admin_menu', array( 'cftp_email_auth', 'add_options_page' ) );

	} // end init

	static function add_options_page() {
		// add ourselves under the bookings menu
		$options_page = add_settings_page( 'Email Authentication',
						  'Email Auth',
						  'administrator',
						  CFTP_EMAIL_AUTH_PLUGIN_NAME.'_settings',
						  array( 'cftp_email_auth', 'display_options_page' )
						);
	} // end add_options_page


	static function display_options_page() {
		global $wpdb;
		//zed1_debug("post=", $_POST);

		$out = '';
		$out .= '<div class="wrap">' . NL;
		$out .= get_screen_icon(CFTP_EMAIL_AUTH_PLUGIN_NAME);
		$out .= '<h2>Email Authentication</h2>' . NL;

		$out .= '<form method="post" action="">';

		// get list of calendars
		$out .= ' <input type="submit" id="iascmatrix" name="iascmatrix" value="' . __('Show Calendar Matrix', 'cftp_email_auth') . '" /></p>' . NL;


		$out .= '</form>';
		$out .= '</div><!-- .wrap -->' . NL;
		echo $out;

	} // end display_options_page

} // end class cftp_email_auth