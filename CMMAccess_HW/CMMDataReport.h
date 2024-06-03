#ifndef _CMMDATAREPORT_H
#define _CMMDATAREPORT_H
namespace CMM
{
	class CMMDataReport
	{
	public:
		CMMDataReport(int type);
		~CMMDataReport();
		virtual int OnDataProcess(void*param);
	};
}
#endif
