
// UpdatePC.h : PROJECT_NAME ���� ���α׷��� ���� �� ��� �����Դϴ�.
//

#pragma once

#ifndef __AFXWIN_H__
	#error "PCH�� ���� �� ������ �����ϱ� ���� 'stdafx.h'�� �����մϴ�."
#endif

#include "resource.h"		// �� ��ȣ�Դϴ�.


// CUpdatePCApp:
// �� Ŭ������ ������ ���ؼ��� UpdatePC.cpp�� �����Ͻʽÿ�.
//

class CUpdatePCApp : public CWinApp
{
public:
	CUpdatePCApp();

// �������Դϴ�.
public:
	virtual BOOL InitInstance();

// �����Դϴ�.

	DECLARE_MESSAGE_MAP()
};

extern CUpdatePCApp theApp;