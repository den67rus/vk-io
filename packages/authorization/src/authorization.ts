import { VK, inspectable } from 'vk-io';

import { createHash } from 'crypto';

import {
	DirectAuthorization,

	ImplicitFlowGroups,
	ImplicitFlowUser,
	ImplicitFlowWebView
} from './providers';

const openAPIProperties = [
	'expire',
	'secret',
	'mid',
	'sid'
];

export class Authorization {
	protected vk: VK;

	/**
	 * Constructor
	 */
	public constructor(vk: VK) {
		this.vk = vk;
	}

	/**
	 * Returns custom tag
	 */
	public get [Symbol.toStringTag](): string {
		return this.constructor.name;
	}

	/**
	 * Standalone authorization with login & password
	 */
	public implicitFlowUser(options = {}): ImplicitFlowUser {
		return new ImplicitFlowUser(this.vk, options);
	}

	/**
	 * Standalone authorization with login & password for group
	 */
	public implicitFlowGroups(groups: number[], options = {}): ImplicitFlowGroups {
		// @ts-ignore
		return new ImplicitFlowGroups(this.vk, { ...options, groups });
	}

	/**
	 * Android apps webview authorization with token apps
	 */
	public ImplicitFlowWebView(options: Partial<{
		sourceUrl: string;
		scope: string | string[];
		token?: string;
		secret?: string;
	}> = {}): ImplicitFlowWebView {
		const { token, appSecret } = this.vk.options;

		if (!options.token) {
			options.token = token;
		}

		if (!options.secret) {
			options.secret = appSecret;
		}
		return new ImplicitFlowWebView(options);
	}

	/**
	 * Direct authorization with login & login in user application
	 */
	public direct(): DirectAuthorization {
		const { appId, appSecret } = this.vk.options;

		return new DirectAuthorization(this.vk, { appId, appSecret });
	}

	/**
	 * Direct authorization with login & login in android application
	 */
	public androidApp(deviceId?: string): DirectAuthorization {
		let genId;
		if (deviceId === undefined) {
			genId = createHash('md5')
				.update(`${new Date()} Android app ID`)
				.digest('hex');
			genId = genId.slice(16);
		}

		return new DirectAuthorization(this.vk, {
			appId: 2274003,
			appSecret: 'hHbZxrka2uZ6jB1inYsH',
			scope: 'full',
			queryParams: {
				device_id: (deviceId === undefined) ? genId : deviceId,
				libverify_support: 1
			}
		});
	}

	/**
	 * Direct authorization with login & login in windows application
	 */
	public windowsApp(): DirectAuthorization {
		return new DirectAuthorization(this.vk, {
			appId: 3697615,
			appSecret: 'AlVXZFMUqyrnABp8ncuU'
		});
	}

	/**
	 * Direct authorization with login & login in windows phone application
	 */
	public windowsPhoneApp(): DirectAuthorization {
		return new DirectAuthorization(this.vk, {
			appId: 3502557,
			appSecret: 'PEObAuQi6KloPM4T30DV'
		});
	}

	/**
	 * Direct authorization with login & login in iphone application
	 */
	public iphoneApp(): DirectAuthorization {
		return new DirectAuthorization(this.vk, {
			appId: 3140623,
			appSecret: 'VeWdmVclDCtn6ihuP1nt'
		});
	}

	/**
	 * Direct authorization with login & login in ipad application
	 */
	public ipadApp(): DirectAuthorization {
		return new DirectAuthorization(this.vk, {
			appId: 3682744,
			appSecret: 'mY6CDUswIVdJLCD3j15n'
		});
	}

	/**
	 * Direct authorization with login & login in VK Me application
	 */
	public vkMeApp(): DirectAuthorization {
		return new DirectAuthorization(this.vk, {
			appId: 6146827,
			appSecret: 'qVxWRF1CwHERuIrKBnqe'
		});
	}

	/**
	 * Verifies that the user is authorized through the Open API
	 */
	public async userAuthorizedThroughOpenAPI(
		params: Record<'expire' | 'mid' | 'secret' | 'sid' | 'sig', string>
	): Promise<{ authorized: boolean }> {
		let sign = ([...openAPIProperties] as (keyof typeof params)[])
			.sort()
			.map(key => `${key}=${params[key]}`)
			.join('');

		sign += this.vk.options.appSecret;
		sign = createHash('md5')
			.update(sign)
			.digest('hex');

		const expire = Number(params.expire);

		const isExpired = Number.isNaN(expire) || expire < (Date.now() / 1000);
		const authorized = params.sig === sign && !isExpired;

		return { authorized };
	}
}

inspectable(Authorization, {
	serialize: () => ({})
});
