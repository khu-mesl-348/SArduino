
// UpdatePCDlg.h : ��� ����
//

#pragma once
#include "afxwin.h"


// CUpdatePCDlg ��ȭ ����
class CUpdatePCDlg : public CDialogEx
{
// �����Դϴ�.
public:
	CUpdatePCDlg(CWnd* pParent = NULL);	// ǥ�� �������Դϴ�.

// ��ȭ ���� �������Դϴ�.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_UPDATEPC_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV �����Դϴ�.


// �����Դϴ�.
protected:
	HICON m_hIcon;

	// ������ �޽��� �� �Լ�
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedBtnFile();
	afx_msg void OnBnClickedBtnUpdate();
	afx_msg void OnBnClickedBtnUpload();
	afx_msg void Wait(DWORD dwMillisecond);
	CEdit m_output_edit;
};
