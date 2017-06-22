package com.mindoo.nginx.auth.utils;

import java.util.Vector;

import lotus.domino.Base;
import lotus.domino.NotesException;
import lotus.domino.Session;

import com.ibm.domino.napi.NException;
import com.ibm.domino.napi.c.NotesUtil;
import com.ibm.domino.napi.c.xsp.XSPNative;

/**
 * Domino utility functions
 * 
 * @author Karsten Lehmann
 */
public class DominoUtilsExt {
	/**
	 * Creates a session for a specified user
	 * 
	 * @param userName user
	 * @return session holder containing session, call {@link SessionHolder#recycle()} when done
	 * @throws Exception
	 */
	public static SessionHolder createSessionAsUser(String userName) throws Exception {
		long hList = NotesUtil.createUserNameList(userName);
		Session session = XSPNative.createXPageSession(userName, hList, true, false);
		SessionHolder holder = new SessionHolder(session, hList);
		return holder;
	}

	public static class SessionHolder implements Base {
		private Session m_session;
		private long m_namesListHandle;

		private SessionHolder(Session session, long namesListHandle) {
			m_session = session;
			m_namesListHandle = namesListHandle;
		}

		public Session getSession() {
			return m_session;
		}

		@Override
		protected void finalize() throws Throwable {
			recycle();
			super.finalize();
		}

		public void recycle() throws NotesException {
			try {
				if (m_session!=null)
					m_session.recycle();
			}
			catch (NotesException e) {
				//ignore
			}
			m_session = null;

			if (m_namesListHandle!=0) {
				try {
					com.ibm.domino.napi.c.Os.OSUnlock(m_namesListHandle);
					com.ibm.domino.napi.c.Os.OSMemFree(m_namesListHandle);
				} catch (NException e) {
					e.printStackTrace();
				}
				m_namesListHandle = 0;
			}
		}

		@Override
		public void recycle(@SuppressWarnings("rawtypes") Vector v) throws NotesException {
			if (v != null) {
				for (Object currValue : v) {
					if (currValue instanceof Base) {
						try {
							((Base)currValue).recycle();
						} catch (NotesException ignore) {}
					}
				}
			}
		}
	}

}
