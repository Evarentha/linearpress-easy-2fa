/*
 * Author: MoyuZJ
 * Team: LinearTeam
 * Contact: linearteam@foxmail.com
 * Made by MoyuZJ in China with ♥
 */

import 'express-session';
declare module 'express-session' {
  interface SessionData {
    /** 密码已通过、等待二次验证的用户 ID（挑战页 / 绑定页期间不写 userId）。 */
    easy2faPendingUserId?: number;
    /** 该会话是否已完成两步验证挑战（强制中间件以此判断放行）。 */
    easy2faPassed?: boolean;
    /** 待确认绑定的 Base32 密钥：生成后须输入有效验证码才正式启用。 */
    easy2faSetupSecret?: string;
    /** WebAuthn 注册挑战（Base64URL），一次性。 */
    easy2faWebauthnRegisterChallenge?: string;
    /** WebAuthn 认证挑战（Base64URL），一次性。 */
    easy2faWebauthnLoginChallenge?: string;
    /** 挑战通过后允许访问的一次性目标（如「查看还原码」页面标记）。 */
    easy2faRevealRecovery?: boolean;
  }
}
