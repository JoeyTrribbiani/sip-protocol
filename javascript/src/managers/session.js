/**
 * 会话状态管理模块
 */

const PROTOCOL_VERSION = 'SIP-1.0';

/**
 * 会话状态类
 */
class SessionState {
  constructor() {
    this.version = PROTOCOL_VERSION;
    this.agentId = '';
    this.remoteAgentId = '';
    this.remotePublicKey = '';
    this.encryptionKey = '';
    this.authKey = '';
    this.replayKey = '';
    this.messageCounter = 0;
    this.pskHash = '';
    this.salt = '';
    this.localNonce = '';
    this.remoteNonce = '';
    this.createdAt = Date.now();
    this.lastActivityAt = Date.now();
  }

  /**
   * 序列化会话状态
   * @returns {String} JSON字符串
   */
  serialize() {
    return JSON.stringify(this);
  }

  /**
   * 反序列化会话状态
   * @param {String} jsonString - JSON字符串
   * @returns {SessionState} 会话状态对象
   */
  static deserialize(jsonString) {
    const data = JSON.parse(jsonString);
    const state = new SessionState();
    Object.assign(state, data);
    return state;
  }

  /**
   * 更新最后活动时间
   */
  updateLastActivity() {
    this.lastActivityAt = Date.now();
  }
}

module.exports = {
  PROTOCOL_VERSION,
  SessionState
};
