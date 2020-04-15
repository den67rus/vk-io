import { URL, URLSearchParams } from 'url';
import { createHash } from 'crypto';
import {
	fetchCookieFollowRedirectsDecorator,
	FetchWrapper,
	RequestInfo,
	RequestInit,
	Response
} from '../fetch-cookie';
import { AuthorizationError } from '../errors';
import { VK_WEB_VIEWS_USER_AGENT, CALLBACK_BLANK, AuthErrorCode } from '../constants';

const {
	AUTHORIZATION_FAILED
} = AuthErrorCode;

export interface IWebViewOptions {
	token: string;
	secret: string;
	scope: string | string[];
	sourceUrl: string;
}

export class ImplicitFlowWebView {
	protected options: Partial<IWebViewOptions>;

	protected fetchCookie!: FetchWrapper;

	public constructor(options: Partial<IWebViewOptions> = {}) {
		if (Array.isArray(options.scope)) {
			options.scope = options.scope.join(',');
		}

		if (typeof options.scope !== 'string') {
			throw new Error('Required option authScope not set');
		}

		if (typeof options.sourceUrl !== 'string') {
			throw new Error('Required option sourceUrl not set');
		}

		if (typeof options.secret !== 'string') {
			throw new Error('Required option secret not set');
		}

		if (typeof options.token !== 'string') {
			throw new Error('Required option token not set');
		}

		this.options = options;

		this.fetchCookie = fetchCookieFollowRedirectsDecorator();
	}

	protected getSign(param: Record<string, string | number>): string {
		let url = '/authorize?';
		for (const key in param) {
			if (Object.prototype.hasOwnProperty.call(param, key)) {
				url += key;
				url += '=';
				url += param[key];
				url += '&';
			}
		}
		url = url.slice(0, -1) + this.options.secret;

		return createHash('md5').update(url).digest('hex');
	}

	protected getToken(): Promise<Response> {
		const urlParam = {
			client_id: '6239898',
			scope: String(this.options.scope),
			redirect_uri: CALLBACK_BLANK,
			source_url: String(this.options.sourceUrl),
			access_token: String(this.options.token),
			display: 'android',
			revoke: '1',
			response_type: 'token',
			v: '5.97'
		};

		const params = new URLSearchParams(urlParam);
		params.append('sig', this.getSign(urlParam));

		const url = new URL(`https://oauth.vk.com/authorize?${params}`);

		return this.fetch(url, {
			method: 'GET'
		});
	}

	protected fetch(
		url: RequestInfo,
		options: RequestInit = {}
	): Promise<Response> {
		const { headers = {} } = options;

		return this.fetchCookie(url, {
			...options,
			compress: false,
			headers: {
				...headers,
				'User-Agent': VK_WEB_VIEWS_USER_AGENT
			}
		});
	}

	public async run(): Promise<{
		token: string;
		expires: number;
		user_id: number;
	}> {
		const response = await this.getToken();

		let params;
		let isOk = true;
		try {
			const url = new URL(response.url);
			params = new URLSearchParams(url.hash.slice(1));

			if (params.get('access_token') === null) {
				isOk = false;
			}
		} catch (e) {
			throw new AuthorizationError({
				message: 'Authorization failed',
				code: AUTHORIZATION_FAILED
			});
		}

		if (isOk) {
			return {
				token: String(params.get('access_token')),
				expires: Number(params.get('expires_in')),
				user_id: Number(params.get('user_id'))
			};
		}

		throw new AuthorizationError({
			message: 'Authorization failed',
			code: AUTHORIZATION_FAILED
		});
	}
}
