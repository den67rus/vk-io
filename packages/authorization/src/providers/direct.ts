import createDebug from 'debug';
import { load as cheerioLoad } from 'cheerio';

import { VK, CaptchaType, ICallbackServiceValidate } from 'vk-io';

import { Agent } from 'https';
import { URL, URLSearchParams } from 'url';

import { AuthorizationError } from '../errors';
import { DESKTOP_USER_AGENT, AuthErrorCode } from '../constants';
import {
	CookieJar,

	FetchWrapper,
	RequestInfo,
	RequestInit,
	Response,

	fetchCookieFollowRedirectsDecorator
} from '../fetch-cookie';
import {
	CheerioStatic,

	getFullURL,
	parseFormField,
	getUsersPermissionsByName
} from '../helpers';

const debug = createDebug('vk-io:authorization:direct');

const {
	INVALID_PHONE_NUMBER,
	AUTHORIZATION_FAILED,
	FAILED_PASSED_CAPTCHA,
	FAILED_PASSED_TWO_FACTOR
} = AuthErrorCode;

/**
 * Number of two-factorial attempts
 */
const TWO_FACTOR_ATTEMPTS = 3;

/**
 * Number of captcha attempts
 */
const CAPTCHA_ATTEMPTS = 3;

/**
 * Phone number check action
 */
const ACTION_SECURITY_CODE = 'act=security';

export interface IDirectAuthOptions {
	appId?: number;
	appSecret?: string;
	authScope?: string;

	login?: string;
	phone?: string | number;
	password?: string;

	agent: Agent;
	scope?: string | number | string[];
	timeout: number;

	apiVersion: string;

	queryParams?: object;
}

export interface IDirectWebViewAuth {
	token: string;
	expires: number;
	refreshToken: string;
}

export class DirectAuthorization {
	protected vk: VK;

	protected options: IDirectAuthOptions;

	public started: boolean;

	public jar!: CookieJar;

	protected fetchCookie!: FetchWrapper;

	protected captchaValidate?: ICallbackServiceValidate;

	protected captchaAttempts = 0;

	protected twoFactorValidate?: ICallbackServiceValidate;

	protected twoFactorAttempts = 0;

	/**
	 * Constructor
	 */
	public constructor(vk: VK, options: Partial<IDirectAuthOptions> = {}) {
		this.vk = vk;

		const {
			appId = vk.options.appId,
			appSecret = vk.options.appSecret,

			login = vk.options.login,
			phone = vk.options.phone,
			password = vk.options.password,

			scope = vk.options.authScope,
			agent = vk.options.agent,
			timeout = vk.options.authTimeout,

			apiVersion = vk.options.apiVersion,

			queryParams
		} = options;

		this.options = {
			appId,
			appSecret,

			login,
			phone,
			password,

			agent,
			scope,
			timeout,

			apiVersion,

			queryParams
		};

		this.started = false;

		this.captchaValidate = undefined;
		this.captchaAttempts = 0;

		this.twoFactorValidate = undefined;
		this.twoFactorAttempts = 0;
	}

	/**
	 * Returns custom tag
	 */
	public get [Symbol.toStringTag](): string {
		return this.constructor.name;
	}

	/**
	 * Executes the HTTP request
	 */
	protected fetch(
		url: RequestInfo,
		options: RequestInit = {}
	): Promise<Response> {
		const { agent, timeout } = this.options;

		const { headers = {} } = options;

		return this.fetchCookie(url, {
			...options,

			agent,
			timeout,
			compress: false,

			headers: {
				...headers,

				'User-Agent': DESKTOP_USER_AGENT
			}
		});
	}

	/**
	 * Returns permission page
	 */
	protected getPermissionsPage(query = {}): Promise<Response> {
		let { scope } = this.options;

		if (scope === 'all' || scope === undefined) {
			throw new Error('Required option authScope not set');
		} else if (scope === 'full') {
			scope = 'nohttps,all';
		} else if (typeof scope !== 'number') {
			scope = getUsersPermissionsByName(scope);
		}

		debug('auth scope %s', scope);

		const {
			appId,
			appSecret,
			login,
			phone,
			password,
			apiVersion,
			queryParams
		} = this.options;

		const params = new URLSearchParams({
			...query,
			...queryParams,
			username: String(login || phone),
			grant_type: 'password',
			client_secret: appSecret,
			'2fa_supported': String(this.vk.callbackService.hasTwoFactorHandler
				? 1
				: 0),
			v: apiVersion,
			client_id: String(appId),
			password,
			scope: String(scope)
		});

		const url = new URL(`https://oauth.vk.com/token?${params}`);

		return this.fetch(url, {
			method: 'GET'
		});
	}

	/**
	 * Runs authorization
	 */
	public async run(): Promise<{
		email?: string;
		user: number;
		token: string;
		expires: number;
		secret: null | string;
		webView: null | IDirectWebViewAuth;
	}> {
		if (this.started) {
			throw new AuthorizationError({
				message: 'Authorization already started!',
				code: AUTHORIZATION_FAILED
			});
		}

		this.started = true;

		this.fetchCookie = fetchCookieFollowRedirectsDecorator();

		let response = await this.getPermissionsPage();
		let text;

		const isProcessed = true;

		while (isProcessed) {
			text = await response.text();

			let isJSON = true;
			try {
				text = JSON.parse(text);
			} catch (e) {
				isJSON = false;
			}

			if (isJSON) {
				if (text.access_token !== undefined) {
					const {
						email,
						user_id: user,
						expires_in: expires,
						access_token: token,
						secret,
						webview_access_token: webViewToken,
						webview_refresh_token: webViewRefreshToken,
						webview_access_token_expires_in: webViewExpires
					} = text;

					let webView: null | IDirectWebViewAuth = null;
					if (webViewToken !== undefined
						&& webViewRefreshToken !== undefined
						&& webViewExpires !== undefined) {
						webView = {
							token: webViewToken,
							expires: Number(webViewExpires),
							refreshToken: webViewRefreshToken
						};
					}

					return {
						email,
						user: user !== undefined
							? Number(user)
							: 0,

						token,
						expires: expires
							? Number(expires)
							: 0,
						secret: secret
							? String(secret)
							: null,
						webView
					};
				}

				if (text.error !== undefined) {
					if (text.error === 'invalid_client') {
						throw new AuthorizationError({
							message: `Invalid client (${text.error_description})`,
							code: AUTHORIZATION_FAILED
						});
					}

					if (text.error === 'need_captcha') {
						response = await this.processCaptcha(text);

						continue;
					}

					if (text.error === 'need_validation') {
						if (text.validation_type !== undefined) {
							response = await this.processTwoFactor(text);

							continue;
						}

						const $ = cheerioLoad(text);

						response = await this.processSecurityForm(response, $);

						continue;
					}

					throw new AuthorizationError({
						message: 'Unsupported type validation',
						code: AUTHORIZATION_FAILED
					});
				}
			}

			throw new AuthorizationError({
				message: 'Authorization failed',
				code: AUTHORIZATION_FAILED
			});
		}

		throw new Error('Fallback error');
	}

	/**
	 * Process captcha
	 */
	protected async processCaptcha(
		{ captcha_sid: sid, captcha_img: src }: {
			captcha_sid: number;
			captcha_img: string;
		}
	): Promise<Response> {
		debug('captcha process');

		if (this.captchaValidate !== undefined) {
			this.captchaValidate.reject(new AuthorizationError({
				message: 'Incorrect captcha code',
				code: FAILED_PASSED_CAPTCHA
			}));

			this.captchaValidate = undefined;

			this.captchaAttempts += 1;
		}

		if (this.captchaAttempts >= CAPTCHA_ATTEMPTS) {
			throw new AuthorizationError({
				message: 'Maximum attempts passage captcha',
				code: FAILED_PASSED_CAPTCHA
			});
		}

		const { key, validate } = await this.vk.callbackService.processingCaptcha({
			type: CaptchaType.DIRECT_AUTH,
			sid,
			src
		});

		this.captchaValidate = validate;

		const response = await this.getPermissionsPage({
			captcha_sid: sid,
			captcha_key: key
		});

		return response;
	}

	/**
	 * Process two-factor
	 */
	protected async processTwoFactor(
		{ validation_type: validationType, phone_mask: phoneMask }: {
			validation_type: string;
			phone_mask: string;
		}
	): Promise<Response> {
		debug('process two-factor handle');

		if (this.twoFactorValidate !== undefined) {
			this.twoFactorValidate.reject(new AuthorizationError({
				message: 'Incorrect two-factor code',
				code: FAILED_PASSED_TWO_FACTOR
			}));

			this.twoFactorValidate = undefined;

			this.twoFactorAttempts += 1;
		}

		if (this.twoFactorAttempts >= TWO_FACTOR_ATTEMPTS) {
			throw new AuthorizationError({
				message: 'Failed passed two-factor authentication',
				code: FAILED_PASSED_TWO_FACTOR
			});
		}

		const { code, validate } = await this.vk.callbackService.processingTwoFactor({
			phoneMask,
			type: validationType === '2fa_app'
				? 'app'
				: 'sms'
		});

		this.twoFactorValidate = validate;

		const response = await this.getPermissionsPage({ code });

		return response;
	}

	/**
	 * Process security form
	 */
	protected async processSecurityForm(response: Response, $: CheerioStatic): Promise<Response> {
		debug('process security form');

		const { login, phone } = this.options;

		let number;
		if (phone !== undefined) {
			number = phone;
		} else if (login !== undefined && !login.includes('@')) {
			number = login;
		} else {
			throw new AuthorizationError({
				message: 'Missing phone number in the phone or login field',
				code: INVALID_PHONE_NUMBER
			});
		}

		if (typeof number === 'string') {
			number = number.trim().replace(/^(\+|00)/, '');
		}

		number = String(number);

		const $field = $('.field_prefix');

		const prefix = $field.first().text().trim().replace('+', '').length;
		const postfix = $field.last().text().trim().length;

		const { action, fields } = parseFormField($);

		fields.code = number.slice(prefix, number.length - postfix);

		const url = getFullURL(action, response);

		const rewResponse = await this.fetch(url, {
			method: 'POST',
			body: new URLSearchParams(fields)
		});

		if (rewResponse.url.includes(ACTION_SECURITY_CODE)) {
			throw new AuthorizationError({
				message: 'Invalid phone number',
				code: INVALID_PHONE_NUMBER
			});
		}

		return rewResponse;
	}
}
