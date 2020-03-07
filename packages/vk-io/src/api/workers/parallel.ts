import { APIRequest } from '../request';
import { sequential } from './sequential';

import { API } from '../api';
import {
	delay,
	getChainReturn,
	resolveExecuteTask
} from '../../utils/helpers';

export async function parallel(api: API, next: Function): Promise<void> {
	// @ts-ignore
	const { queue } = api;

	if (queue[0].method.startsWith('execute')) {
		// @ts-ignore
		sequential(api, next);

		return;
	}

	// Wait next event loop, saves one request or more
	await delay(0);

	// @ts-ignore
	const { apiExecuteCount } = api.vk.options;

	const tasks: APIRequest[] = [];

	for (let i = 0; i < queue.length; i += 1) {
		if (queue[i].method.startsWith('execute')) {
			continue;
		}

		const [request] = queue.splice(i, 1);

		i -= 1;

		tasks.push(request);

		if (tasks.length >= apiExecuteCount) {
			break;
		}
	}

	try {
		const request = new APIRequest({
			// @ts-ignore
			vk: api.vk,
			method: 'execute',
			params: {
				code: getChainReturn(tasks.map(String))
			}
		});

		// @ts-ignore
		api.callMethod(request);

		next();

		resolveExecuteTask(tasks, await request.promise);
	} catch (error) {
		for (const task of tasks) {
			task.reject(error);
		}
	}
}
