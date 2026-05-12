/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include <fstream>
#include <stdio.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "CoreMacOSX.h"
#include "Driver/Fuse/FuseService.h"
#include "Core/Unix/CoreServiceProxy.h"
#include "Platform/FileStream.h"
#include "Platform/MemoryStream.h"
#include "Platform/Serializable.h"
#include "Platform/SystemLog.h"

namespace VeraCrypt
{
	static string DecodePlistXmlString (const string &xmlString)
	{
		string decoded;

		for (size_t i = 0; i < xmlString.size(); ++i)
		{
			if (xmlString[i] != '&')
			{
				decoded += xmlString[i];
				continue;
			}

			if (xmlString.compare (i, 5, "&amp;") == 0)
			{
				decoded += '&';
				i += 4;
			}
			else if (xmlString.compare (i, 4, "&lt;") == 0)
			{
				decoded += '<';
				i += 3;
			}
			else if (xmlString.compare (i, 4, "&gt;") == 0)
			{
				decoded += '>';
				i += 3;
			}
			else if (xmlString.compare (i, 6, "&quot;") == 0)
			{
				decoded += '"';
				i += 5;
			}
			else if (xmlString.compare (i, 6, "&apos;") == 0)
			{
				decoded += '\'';
				i += 5;
			}
			else
				decoded += xmlString[i];
		}

		return decoded;
	}

	static bool ExtractPlistString (const string &xml, const string &key, size_t start, size_t limit, string &value, size_t *endPos = nullptr)
	{
		// hdiutil currently emits simple <key>name</key><string>value</string> pairs.
		string keyTag = "<key>" + key + "</key>";
		size_t p = xml.find (keyTag, start);
		if (p == string::npos || p >= limit)
			return false;

		p = xml.find ("<string>", p + keyTag.size());
		if (p == string::npos || p >= limit)
			return false;
		p += 8;

		size_t e = xml.find ("</string>", p);
		if (e == string::npos || e > limit)
			return false;

		value = DecodePlistXmlString (xml.substr (p, e - p));
		if (endPos)
			*endPos = e + 9;

		return true;
	}

	static string NormalizeDiskImagePath (const string &path)
	{
		string normalized;
		bool previousSlash = false;

		for (string::const_iterator i = path.begin(); i != path.end(); ++i)
		{
			if (*i == '/')
			{
				if (previousSlash)
					continue;

				previousSlash = true;
			}
			else
				previousSlash = false;

			normalized += *i;
		}

		if (normalized.find ("/private/") == 0)
			normalized.erase (0, 8);

		return normalized;
	}

	static DevicePath FindVirtualDeviceByImagePath (const string &imagePath)
	{
		list <string> args;
		args.push_back ("info");
		args.push_back ("-plist");

		string xml = Process::Execute ("/usr/bin/hdiutil", args);
		string normalizedImagePath = NormalizeDiskImagePath (imagePath);

		for (size_t p = 0; ; )
		{
			size_t imageKeyPos = xml.find ("<key>image-path</key>", p);
			if (imageKeyPos == string::npos)
				break;

			string currentImagePath;
			size_t imageValueEnd = 0;
			if (!ExtractPlistString (xml, "image-path", imageKeyPos, string::npos, currentImagePath, &imageValueEnd))
			{
				p = imageKeyPos + 1;
				continue;
			}

			size_t nextImageKeyPos = xml.find ("<key>image-path</key>", imageValueEnd);
			if (NormalizeDiskImagePath (currentImagePath) == normalizedImagePath)
			{
				string devEntry;
				if (ExtractPlistString (xml, "dev-entry", imageValueEnd, nextImageKeyPos, devEntry))
					return StringConverter::Trim (devEntry);
			}

			p = imageValueEnd;
		}

		return DevicePath();
	}

	static bool AuxiliaryControlFileHasVirtualDevice (const DirectoryPath &auxMountPoint, const DevicePath &virtualDev, int retryCount = 50)
	{
		for (int t = 0; t < retryCount; ++t)
		{
			try
			{
				shared_ptr <File> controlFile (new File);
				controlFile->Open (string (auxMountPoint) + FuseService::GetControlPath());

				FileStream controlFileReader (controlFile);
				string controlFileData = controlFileReader.ReadToEnd();
				if (controlFileData.empty() || controlFileData.size() > 1024 * 1024)
					throw ParameterIncorrect (SRC_POS);

				shared_ptr <Stream> controlFileStream (new MemoryStream (ConstBufferPtr ((const uint8 *) controlFileData.data(), controlFileData.size())));
				shared_ptr <VolumeInfo> mountedVol = Serializable::DeserializeNew <VolumeInfo> (controlFileStream);
				if (mountedVol && string (mountedVol->VirtualDevice) == string (virtualDev))
					return true;
			}
			catch (...) { }

			Thread::Sleep (100);
		}

		return false;
	}

	CoreMacOSX::CoreMacOSX ()
	{
	}

	CoreMacOSX::~CoreMacOSX ()
	{
	}

	shared_ptr <VolumeInfo> CoreMacOSX::DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo)
	{
		if (mountedVolume->VirtualDevice.IsEmpty() && !mountedVolume->AuxMountPoint.IsEmpty())
		{
			try
			{
				DevicePath recoveredVirtualDevice = FindVirtualDeviceByImagePath (string (mountedVolume->AuxMountPoint) + FuseService::GetVolumeImagePath());
				if (!recoveredVirtualDevice.IsEmpty())
					mountedVolume->VirtualDevice = recoveredVirtualDevice;
			}
			catch (...) { }
		}

		if (!mountedVolume->VirtualDevice.IsEmpty() && mountedVolume->VirtualDevice.IsBlockDevice())
		{
			list <string> args;
			args.push_back ("detach");
			args.push_back (mountedVolume->VirtualDevice);

			if (ignoreOpenFiles)
				args.push_back ("-force");

			try
			{
				Process::Execute ("/usr/bin/hdiutil", args);
			}
			catch (ExecutedProcessFailed &e)
			{
				if (!ignoreOpenFiles)
				{
					string err = e.GetErrorOutput();

					if (err.find ("couldn't unmount") != string::npos
						|| err.find ("busy") != string::npos
						|| err.find ("49153") != string::npos)
					{
						throw MountedVolumeInUse (SRC_POS);
					}
				}

				throw;
			}
		}

		if (syncVolumeInfo || mountedVolume->Protection == VolumeProtection::HiddenVolumeReadOnly)
		{
			sync();
			VolumeInfoList ml = GetMountedVolumes (mountedVolume->Path);

			if (ml.size() > 0)
				mountedVolume = ml.front();
		}

		list <string> args;
		args.push_back ("--");
		args.push_back (mountedVolume->AuxMountPoint);

		for (int t = 0; true; t++)
		{
			try
			{
				Process::Execute ("/sbin/umount", args);
				break;
			}
			catch (ExecutedProcessFailed&)
			{
				if (t > 10)
					throw;
				Thread::Sleep (200);
			}
		}

		try
		{
			mountedVolume->AuxMountPoint.Delete();
		}
		catch (...)	{ }

		return mountedVolume;
	}

	void CoreMacOSX::CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair) const
	{
		list <string> args;
		struct stat sb;

		if (stat("/Applications/Utilities/Disk Utility.app", &sb) == 0)
			args.push_back ("/Applications/Utilities/Disk Utility.app");
		else
			args.push_back ("/System/Applications/Utilities/Disk Utility.app");

		Process::Execute ("/usr/bin/open", args);
	}

	DevicePath CoreMacOSX::MountAuxVolumeImage (const DirectoryPath &auxMountPoint, const MountOptions &options) const
	{
#ifndef VC_MACOSX_FUSET
		// Check FUSE version
		char fuseVersionString[MAXHOSTNAMELEN + 1] = { 0 };
		size_t fuseVersionStringLength = MAXHOSTNAMELEN;
		int status;

		if ((status = sysctlbyname ("osxfuse.version.number", fuseVersionString, &fuseVersionStringLength, NULL, 0)) != 0)
		{
			fuseVersionStringLength = MAXHOSTNAMELEN;
			if ((status = sysctlbyname ("vfs.generic.osxfuse.version.number", fuseVersionString, &fuseVersionStringLength, NULL, 0)) != 0)
			{
				fuseVersionStringLength = MAXHOSTNAMELEN;
				if ((status = sysctlbyname ("vfs.generic.macfuse.version.number", fuseVersionString, &fuseVersionStringLength, NULL, 0)) != 0)
				{
					throw HigherFuseVersionRequired (SRC_POS);
				}
			}
		}

		// look for OSXFuse dynamic library
		struct stat sb;
		if (0 != stat("/usr/local/lib/libosxfuse_i64.2.dylib", &sb) && 0 != stat("/usr/local/lib/libfuse.dylib", &sb))
		{
			throw HigherFuseVersionRequired (SRC_POS);
		}

		vector <string> fuseVersion = StringConverter::Split (string (fuseVersionString), ".");
		if (fuseVersion.size() < 2)
			throw HigherFuseVersionRequired (SRC_POS);

		uint32 fuseVersionMajor = StringConverter::ToUInt32 (fuseVersion[0]);
		uint32 fuseVersionMinor = StringConverter::ToUInt32 (fuseVersion[1]);

		if (fuseVersionMajor < 2 || (fuseVersionMajor == 2 && fuseVersionMinor < 5))
			throw HigherFuseVersionRequired (SRC_POS);
#endif
		// Mount volume image
		string volImage = string (auxMountPoint) + FuseService::GetVolumeImagePath();

		list <string> args;
		args.push_back ("attach");
		args.push_back (volImage);
		args.push_back ("-plist");
		args.push_back ("-noautofsck");
		args.push_back ("-imagekey");
		args.push_back ("diskimage-class=CRawDiskImage");

		if (!options.NoFilesystem && options.MountPoint && !options.MountPoint->IsEmpty())
		{
			args.push_back ("-mount");
			args.push_back ("required");

			// Let the system specify mount point except when the user specified a non-default one
			if (string (*options.MountPoint).find (GetDefaultMountPointPrefix()) != 0)
			{
				args.push_back ("-mountpoint");
				args.push_back (*options.MountPoint);
			}
		}
		else
			args.push_back ("-nomount");

		if (options.Protection == VolumeProtection::ReadOnly)
			args.push_back ("-readonly");

		string xml;

		while (true)
		{
			try
			{
				xml = Process::Execute ("/usr/bin/hdiutil", args);
				break;
			}
			catch (ExecutedProcessFailed &e)
			{
				if (e.GetErrorOutput().find ("noautofsck") != string::npos)
				{
					args.remove ("-noautofsck");
					continue;
				}

				throw;
			}
		}

		size_t p = xml.find ("<key>dev-entry</key>");
		if (p == string::npos)
			throw ParameterIncorrect (SRC_POS);

		p = xml.find ("<string>", p);
		if (p == string::npos)
			throw ParameterIncorrect (SRC_POS);
		p += 8;

		size_t e = xml.find ("</string>", p);
		if (e == string::npos)
			throw ParameterIncorrect (SRC_POS);

		DevicePath virtualDev = StringConverter::Trim (xml.substr (p, e - p));

		try
		{
			FuseService::SendAuxDeviceInfo (auxMountPoint, virtualDev);
#ifndef VC_MACOSX_FUSET
			if (!AuxiliaryControlFileHasVirtualDevice (auxMountPoint, virtualDev))
			{
				stringstream logMessage;
				logMessage << "VeraCrypt auxiliary mount did not report hdiutil device after mount: "
					<< string (auxMountPoint) << FuseService::GetControlPath()
					<< ", expected " << string (virtualDev);
				SystemLog::WriteError (logMessage.str());

				throw TimeOut (SRC_POS);
			}
#endif
		}
		catch (...)
		{
			try
			{
				list <string> args;
				args.push_back ("detach");
				args.push_back (virtualDev);
				args.push_back ("-force");

				Process::Execute ("/usr/bin/hdiutil", args);
			}
			catch (ExecutedProcessFailed&) { }
			throw;
		}

#ifdef VC_MACOSX_FUSET
		if (!AuxiliaryControlFileHasVirtualDevice (auxMountPoint, virtualDev, 10))
		{
			stringstream logMessage;
			logMessage << "VeraCrypt auxiliary mount did not report hdiutil device after mount: "
				<< string (auxMountPoint) << FuseService::GetControlPath()
				<< ", expected " << string (virtualDev)
				<< "; continuing with hdiutil device";
			SystemLog::WriteError (logMessage.str());
		}
#endif

		return virtualDev;
	}

	unique_ptr <CoreBase> Core (new CoreServiceProxy <CoreMacOSX>);
	unique_ptr <CoreBase> CoreDirect (new CoreMacOSX);
}
