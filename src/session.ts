/*
 * LinearPress Session
 *
 * Implements the session module for LinearPress.
 *
 * Authors:
 * MoyuZJ <moyuzj@moyuzj.cn> @LinearTeam - Made in China with ♥
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { Request } from 'express';

/** Grant the verified login state only after successful session regeneration. */
export function completeLogin(req: Pick<Request, 'session'>, userId: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) return reject(error);
      req.session.userId = userId;
      req.session.easy2faPassed = true;
      resolve();
    });
  });
}
