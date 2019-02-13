
// UpdatePCDlg.cpp : ���� ����
//

#include "stdafx.h"
#include "UpdatePC.h"
#include "UpdatePCDlg.h"
#include "afxdialogex.h"
#include <stdio.h>
#include <string>
#include "SerialClass.h" // Library described above
#include "sha256.h"
#include "crc16.h"
#include <conio.h>


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define MAX_PIPE_BUFF_SIZE 1000
int m_run_flag = 0;
TCHAR m_current_path[MAX_PATH];
SECURITY_ATTRIBUTES m_security_attributes;
PROCESS_INFORMATION  m_process_info;

HANDLE mh_pipe_read = NULL;
HANDLE mh_pipe_write = NULL;

Serial* SP = new Serial("\\\\.\\COM4");    // adjust as needed

// ���� ���α׷� ������ ���Ǵ� CAboutDlg ��ȭ �����Դϴ�.

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// ��ȭ ���� �������Դϴ�.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV �����Դϴ�.

// �����Դϴ�.
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CUpdatePCDlg ��ȭ ����



CUpdatePCDlg::CUpdatePCDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_UPDATEPC_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CUpdatePCDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	//DDX_Control(pDX, IDC_LIST, m_list);
	DDX_Control(pDX, IDC_EDIT1, m_output_edit);
}

BEGIN_MESSAGE_MAP(CUpdatePCDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BTN_FILE, &CUpdatePCDlg::OnBnClickedBtnFile)
	ON_BN_CLICKED(IDC_BTN_UPDATE, &CUpdatePCDlg::OnBnClickedBtnUpdate)
	ON_BN_CLICKED(IDC_BTN_UPLOAD, &CUpdatePCDlg::OnBnClickedBtnUpload)
END_MESSAGE_MAP()


// CUpdatePCDlg �޽��� ó����

BOOL CUpdatePCDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// �ý��� �޴��� "����..." �޴� �׸��� �߰��մϴ�.

	// IDM_ABOUTBOX�� �ý��� ��� ������ �־�� �մϴ�.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// �� ��ȭ ������ �������� �����մϴ�.  ���� ���α׷��� �� â�� ��ȭ ���ڰ� �ƴ� ��쿡��
	//  �����ӿ�ũ�� �� �۾��� �ڵ����� �����մϴ�.
	SetIcon(m_hIcon, TRUE);			// ū �������� �����մϴ�.
	SetIcon(m_hIcon, FALSE);		// ���� �������� �����մϴ�.

	// TODO: ���⿡ �߰� �ʱ�ȭ �۾��� �߰��մϴ�.
	return TRUE;  // ��Ŀ���� ��Ʈ�ѿ� �������� ������ TRUE�� ��ȯ�մϴ�.
}

void CUpdatePCDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// ��ȭ ���ڿ� �ּ�ȭ ���߸� �߰��� ��� �������� �׸�����
//  �Ʒ� �ڵ尡 �ʿ��մϴ�.  ����/�� ���� ����ϴ� MFC ���� ���α׷��� ��쿡��
//  �����ӿ�ũ���� �� �۾��� �ڵ����� �����մϴ�.

void CUpdatePCDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // �׸��⸦ ���� ����̽� ���ؽ�Ʈ�Դϴ�.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Ŭ���̾�Ʈ �簢������ �������� ����� ����ϴ�.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// �������� �׸��ϴ�.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// ����ڰ� �ּ�ȭ�� â�� ���� ���ȿ� Ŀ���� ǥ�õǵ��� �ý��ۿ���
//  �� �Լ��� ȣ���մϴ�.
HCURSOR CUpdatePCDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CUpdatePCDlg::OnBnClickedBtnFile()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
	static TCHAR BASED_CODE szFilter[] = _T("���̳ʸ� ����(*.BIN, *.HEX) | *.bin; *.hex | �������(*.*)|*.*||");
	CFileDialog dlg(TRUE, _T("*.bin"), _T("binary"), OFN_HIDEREADONLY, szFilter);
	if (IDOK == dlg.DoModal()) {
		CString pathName = dlg.GetPathName();

		m_output_edit.SetWindowTextA(pathName + " is selected");
		//ShellExecute(NULL, "open", pathName, NULL, NULL, SW_SHOW);
	}
	
}


void CUpdatePCDlg::OnBnClickedBtnUpdate()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
	m_output_edit.ReplaceSel("==========================\r\n");
	m_output_edit.ReplaceSel("VP Update is starting.....\r\n");
	m_output_edit.ReplaceSel("==========================\r\n\r\n");
	Wait(300);

	FILE *fp;
	int fileSize = 0;
	CSha256 c = { 0, };
	Byte digest[32] = { 0, };
	char *buf = NULL;

	Byte digest_test[32] = { 0x01 ,0x02, 0x03, 0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x30,0x31,0x32 };
	Byte OwnershipPW[11] = { 0x00, 0x01, 0x00, 0x08, 0x08, 0x05, 0x09, 0x06, 0x07, 0x09, 0x03 };

	unsigned short crc;
	char* crcbuf = NULL;
	char crcvalue[3];

	// Firmware hash start
	if ((fp = fopen("Final_AP.ino.mega.bin", "rb")) == NULL) {
		m_output_edit.ReplaceSel("File open Error\r\n");
		exit(1);
	}

	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	buf = new char[fileSize];
	fread(buf, 1, fileSize, fp);

	Sha256_Init(&c);
	Sha256_Update(&c, (Byte*)buf, fileSize);
	Sha256_Final(&c, digest);

	fclose(fp);
	delete buf;
	memset(&c, 0x00, sizeof(c));
	// Firmware hash end

	Wait(100);
	m_output_edit.ReplaceSel("Welcome to the serial test app!\r\n");

	if (SP->IsConnected()) {
		Wait(100);
		m_output_edit.ReplaceSel("We're connected\r\n");
		Wait(100);
	}

	BYTE dataPacket[47];
	char arduino_Result[10] = "";
	int dataLength = 10;
	int readResult = 0;
	bool writeResult = false;

	memset(dataPacket, 0, 47);
	dataPacket[0] = 0x00; // Type[1]
	dataPacket[1] = 0x08; // New Firmware Version[1]
	for (int i = 0; i<32; i++) // New Firmware Hash[32]
		dataPacket[i + 2] = digest_test[i];
	for (int i = 0; i < 11; i++) //Ownership PW[11]
		dataPacket[i + 34] = OwnershipPW[i];

	// �۽����� CRC ����
	gen_crc_table();

	crc = update_crc(0, (unsigned char*)digest_test, 32);
	Wait(100);

	*(unsigned short*)crcvalue = crc;
	dataPacket[45] = crcvalue[1];
	dataPacket[46] = crcvalue[0];

	unsigned char out[34];
	for (int i = 0; i<32; i++)
		out[i] = digest_test[i];
	out[32] = (crc & 0xff00) >> 8;
	out[33] = (crc & 0x00ff);

	unsigned short check = update_crc(0, out, 34);

	while (SP->IsConnected())
	{
		writeResult = SP->WriteData(dataPacket, 47);

		if (writeResult == true)
			m_output_edit.ReplaceSel("write success\r\n");
		else
			m_output_edit.ReplaceSel("write failed\r\r\n");

		while ((readResult = SP->ReadData((byte*)arduino_Result, dataLength)) != 1) {}
		std::string test(arduino_Result);

		if (test.compare("1") == 0) {
			test = "";
			memset(arduino_Result, 0, 10);
			m_output_edit.ReplaceSel("VP update SUCCESS\r\n");
			SP->~Serial();
			return;
		}
		else if (test.compare("2") == 0) {
			test = "";
			m_output_edit.ReplaceSel("Ownership PW Error\r\n");
			memset(arduino_Result, 0, 10);
			return;
		}
		else if (test.compare("3") == 0) {
			test = "";
			m_output_edit.ReplaceSel("Current Pin Code Error\r\n");
			memset(arduino_Result, 0, 10);
			return;
		}
		else if (test.compare("4") == 0) {
			test = "";
			m_output_edit.ReplaceSel("Old Firmware Error\r\n");
			memset(arduino_Result, 0, 10);
			return;
		}
		else if (test.compare("5") == 0) {
			test = "";
			m_output_edit.ReplaceSel("CRC Error\r\n");
			memset(arduino_Result, 0, 10);
			return;
		}
		else if (test.compare("6") == 0) {
			test = "";
			m_output_edit.ReplaceSel("Hash Verify Error\r\n");
			memset(arduino_Result, 0, 10);
			return;
		}
		else if (test.compare("7") == 0) {
			test = "";
			m_output_edit.ReplaceSel("Unknown Error\r\n");
			memset(arduino_Result, 0, 10);
			return;
		}
	}
	return;
}

void CUpdatePCDlg::OnBnClickedBtnUpload()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
	m_output_edit.ReplaceSel("================================\r\n");
	m_output_edit.ReplaceSel("Firmware Upload is starting.....\r\n");
	m_output_edit.ReplaceSel("================================\r\n\r\n");
	Wait(300);
		
	#define EXECDOSCMD "dir c:" // can be replaced with your command 
	#define EXETEST "dir d:"
	SECURITY_ATTRIBUTES sa;
	HANDLE hRead, hWrite;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	SP->~Serial();

	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
	{
		return;
	}
	char command[2048]; // up to 1K of the command line, good enough for now 
	strcpy(command, "avrdude -CC:/Users/MESL/AppData/Local/Arduino15/packages/arduino/tools/avrdude/6.3.0-arduino8/etc/avrdude.conf -v -patmega2560 -cwiring -PCOM4 -b115200 -D -Uflash:w:C:/Users/MESL/Desktop/UpdatePC/UpdatePC/Final_AP.ino.mega,hex:i");
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	si.cb = sizeof(STARTUPINFO);
	GetStartupInfo(&si);
	si.hStdError = hWrite; // create a process to standard error output redirected to pipes to 
	si.hStdOutput = hWrite; // create a process to standard output redirected to pipes to 
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	// Key step, CreateProcess function arguments meaning please refer to MSDN 
	if (!CreateProcess(NULL, command, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
	{
		CloseHandle(hWrite);
		CloseHandle(hRead);
		return;
	}
	CloseHandle(hWrite);
	char buffer[4096] = { 0 }; // with 4K of space to store the contents of the output, if not display the file contents, under normal circumstances is enough. 
	DWORD bytesRead;
	while (true)
	{
		if (ReadFile(hRead, buffer, 4096, &bytesRead, NULL) == NULL)
			break;

		int nLen = m_output_edit.GetWindowTextLength();
		m_output_edit.SetSel(nLen, nLen);
		m_output_edit.ReplaceSel(buffer);

		memset(buffer, 0, 4096);
	}

	CloseHandle(hRead);

	m_output_edit.ReplaceSel("============================\r\n");
	m_output_edit.ReplaceSel("Secure Boot is starting.....\r\n");
	m_output_edit.ReplaceSel("============================\r\n\r\n");
	Wait(300);

	SP = new Serial("\\\\.\\COM9");
	//���� ��ť���Ʈ�� ����� ����Ǵ��� Ȯ���Ѵ�
	int readResult = 0;
	char arduino_Result[10] = "";
	int dataLength = 10;
	CString str;

	while (SP->IsConnected()) {
		Wait(500);
		m_output_edit.ReplaceSel("Serial connected\r\n");
		while ((readResult = SP->ReadData((byte*)arduino_Result, dataLength)) != 1) {}

		std::string test(arduino_Result);
		str.Format("Result: %c\r\n", arduino_Result[0]);
		m_output_edit.ReplaceSel(str);

		if (test.compare("6") == 0) {
			test = "";
			m_output_edit.ReplaceSel("Hash Verify error\r\n");
			memset(arduino_Result, 0, 10);
			return;
		}
		else if (test.compare("3") == 0) {
			test = "";
			m_output_edit.ReplaceSel("Current Pin Code Error\r\n");
			memset(arduino_Result, 0, 10);
			return;
		}
		else if (test.compare("1") == 0) {
			test = "";
			m_output_edit.ReplaceSel("Secure Boot Success\r\n");
			memset(arduino_Result, 0, 10);
			return;
		}
	}
	return;
}

void CUpdatePCDlg::Wait(DWORD dwMillisecond) {
	MSG msg;
	DWORD dwStart;
	dwStart = GetTickCount();

	while (GetTickCount() - dwStart < dwMillisecond)
	{
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
}