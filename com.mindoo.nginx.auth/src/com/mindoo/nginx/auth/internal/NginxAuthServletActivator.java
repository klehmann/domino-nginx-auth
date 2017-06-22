package com.mindoo.nginx.auth.internal;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class NginxAuthServletActivator implements BundleActivator {
	public static final String PLUGIN_ID = "com.mindoo.nginx.auth";
	
	private static BundleContext context;

	static BundleContext getContext() {
		return context;
	}

	/*
	 * (non-Javadoc)
	 * @see org.osgi.framework.BundleActivator#start(org.osgi.framework.BundleContext)
	 */
	public void start(BundleContext bundleContext) throws Exception {
		NginxAuthServletActivator.context = bundleContext;
	}

	/*
	 * (non-Javadoc)
	 * @see org.osgi.framework.BundleActivator#stop(org.osgi.framework.BundleContext)
	 */
	public void stop(BundleContext bundleContext) throws Exception {
		NginxAuthServletActivator.context = null;
	}

}
